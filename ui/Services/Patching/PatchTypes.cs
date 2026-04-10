using System;

namespace CloudRedirect.Services.Patching
{
    /// <summary>
    /// AES-256 key used by SteamTools to encrypt/decrypt the payload cache.
    /// Shared between Patcher (decrypt + re-encrypt) and Fingerprint (validation).
    /// </summary>
    internal static class SteamToolsCrypto
    {
        internal static readonly byte[] AesKey =
        {
            0x31, 0x4C, 0x20, 0x86, 0x15, 0x05, 0x74, 0xE1,
            0x5C, 0xF1, 0x1D, 0x1B, 0xC1, 0x71, 0x25, 0x1A,
            0x47, 0x08, 0x6C, 0x00, 0x26, 0x93, 0x55, 0xCD,
            0x51, 0xC9, 0x3A, 0x42, 0x3C, 0x14, 0x02, 0x94,
        };
    }

    internal record PatchEntry(int Offset, byte[] Original, byte[] Replacement);

    internal enum ScanRegion
    {
        Text,       // .text section only
        Obfuscated, // first non-standard section (the obfuscated code section)
        All,        // entire file
    }

    /// <summary>
    /// Declarative patch definition: pattern + mask to locate the patch site,
    /// with optional post-match validator for complex signatures.
    /// </summary>
    internal class PatternPatch
    {
        public string Name { get; init; }
        public byte[] Pattern { get; init; }
        public byte[] Mask { get; init; }
        public int PatchOffset { get; init; }
        public byte[] Original { get; init; }
        public byte[] Replacement { get; init; }
        public ScanRegion Region { get; init; }

        // wildcard bytes in Original/Replacement that get snapshotted from actual data
        public int WildcardStart { get; init; }
        public int WildcardLen { get; init; }

        // optional: if the pattern is too generic, this callback validates a candidate match.
        // receives (fileData, matchOffset) and returns true if this is the right match.
        public Func<byte[], int, bool> Validator { get; init; }

        // optional: when the patch site isn't at a fixed offset from the pattern match,
        // this callback resolves the actual patch offset given (fileData, matchOffset).
        // returns the file offset of the patch site, or -1 if not found.
        public Func<byte[], int, int> PatchSiteResolver { get; init; }

        // optional: scan relative to a previous patch's resolved offset instead of section start.
        // when set, scanning starts at (previousOffset + RelativeStart) and ends at
        // (previousOffset + RelativeEnd). the int[] index refers to earlier patches in the group.
        public int? RelativeToPatchIndex { get; init; }
        public int RelativeStart { get; init; }
        public int RelativeEnd { get; init; }
    }

    internal enum PatchState
    {
        NotInstalled,
        Unpatched,
        Patched,
        PartiallyPatched,
        UnknownVersion,
        OutOfDate,
    }

    internal class PatchResult
    {
        public bool Succeeded { get; set; }
        public bool DllPatched { get; set; }
        public bool CachePatched { get; set; }
        public string Error { get; set; }

        public PatchResult Fail(string error)
        {
            Succeeded = false;
            Error = error;
            return this;
        }
    }

    internal readonly struct PeSection
    {
        public readonly string Name;
        public readonly uint VirtualAddress;
        public readonly uint VirtualSize;
        public readonly uint RawOffset;
        public readonly uint RawSize;
        public readonly uint Characteristics;

        // IMAGE_SCN_MEM_EXECUTE
        private const uint SCN_MEM_EXECUTE = 0x20000000;

        public bool IsExecutable => (Characteristics & SCN_MEM_EXECUTE) != 0;

        public PeSection(string name, uint va, uint vsize, uint raw, uint rawSize, uint characteristics = 0)
        {
            Name = name;
            VirtualAddress = va;
            VirtualSize = vsize;
            RawOffset = raw;
            RawSize = rawSize;
            Characteristics = characteristics;
        }

        public static PeSection[] Parse(byte[] pe)
        {
            if (pe.Length < 64) return Array.Empty<PeSection>();

            int peOff = BitConverter.ToInt32(pe, 0x3C);
            if (peOff < 0 || peOff + 24 > pe.Length) return Array.Empty<PeSection>();
            if (pe[peOff] != 'P' || pe[peOff + 1] != 'E') return Array.Empty<PeSection>();

            int numSections = BitConverter.ToUInt16(pe, peOff + 6);
            if (numSections > 96) return Array.Empty<PeSection>();

            int optSize = BitConverter.ToUInt16(pe, peOff + 20);
            int firstSection = peOff + 24 + optSize;
            if (firstSection > pe.Length) return Array.Empty<PeSection>();

            var result = new PeSection[numSections];
            int populated = 0;
            for (int i = 0; i < numSections; i++)
            {
                int off = firstSection + i * 40;
                if (off + 40 > pe.Length) break;

                int nameEnd = 0;
                for (int j = 0; j < 8 && pe[off + j] != 0; j++) nameEnd = j + 1;
                string name = System.Text.Encoding.ASCII.GetString(pe, off, nameEnd);

                uint vsize = BitConverter.ToUInt32(pe, off + 8);
                uint va = BitConverter.ToUInt32(pe, off + 12);
                uint rawSize = BitConverter.ToUInt32(pe, off + 16);
                uint rawPtr = BitConverter.ToUInt32(pe, off + 20);
                uint chars = BitConverter.ToUInt32(pe, off + 36);

                result[i] = new PeSection(name, va, vsize, rawPtr, rawSize, chars);
                populated++;
            }
            if (populated < numSections)
                Array.Resize(ref result, populated);
            return result;
        }

        public static PeSection? Find(PeSection[] sections, string name)
        {
            for (int i = 0; i < sections.Length; i++)
                if (sections[i].Name == name) return sections[i];
            return null;
        }

        // file offset -> RVA, returns -1 if outside any section
        public static int FileOffsetToRva(PeSection[] sections, int fileOffset)
        {
            if (fileOffset < 0) return -1;
            uint fo = (uint)fileOffset;
            for (int i = 0; i < sections.Length; i++)
            {
                var s = sections[i];
                if (fo >= s.RawOffset && fo - s.RawOffset < s.RawSize)
                    return (int)(s.VirtualAddress + (fo - s.RawOffset));
            }
            return -1;
        }

        // RVA -> file offset, returns -1 if in BSS or outside any section
        public static int RvaToFileOffset(PeSection[] sections, int rva)
        {
            if (rva < 0) return -1;
            uint r = (uint)rva;
            for (int i = 0; i < sections.Length; i++)
            {
                var s = sections[i];
                long size = Math.Max(s.VirtualSize, s.RawSize);
                if (r >= s.VirtualAddress && r - s.VirtualAddress < (uint)size)
                {
                    uint offsetInSection = r - s.VirtualAddress;
                    if (offsetInSection >= s.RawSize)
                        return -1; // in BSS / zero-fill region, no file backing
                    return (int)(s.RawOffset + offsetInSection);
                }
            }
            return -1;
        }

        public static PeSection? FindByFileOffset(PeSection[] sections, int fileOffset)
        {
            if (fileOffset < 0) return null;
            uint fo = (uint)fileOffset;
            for (int i = 0; i < sections.Length; i++)
            {
                var s = sections[i];
                if (fo >= s.RawOffset && fo < s.RawOffset + s.RawSize)
                    return s;
            }
            return null;
        }

        /// <summary>
        /// Find the section that contains the given RVA (using VirtualAddress + VirtualSize).
        /// Unlike RvaToFileOffset, this succeeds for BSS regions that have no file backing.
        /// </summary>
        public static PeSection? FindByRva(PeSection[] sections, int rva)
        {
            if (rva < 0) return null;
            uint r = (uint)rva;
            for (int i = 0; i < sections.Length; i++)
            {
                var s = sections[i];
                long size = Math.Max(s.VirtualSize, s.RawSize);
                if (r >= s.VirtualAddress && r - s.VirtualAddress < (uint)size)
                    return s;
            }
            return null;
        }
    }
}
