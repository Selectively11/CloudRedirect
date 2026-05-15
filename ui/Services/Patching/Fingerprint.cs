using System;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace CloudRedirect.Services.Patching
{
    internal static class Fingerprint
    {
        public static string? FindCachePath(string steamPath, bool verbose = true, Action<string>? log = null)
        {
            var cacheDir = Path.Combine(steamPath, "appcache", "httpcache", "3b");
            if (!Directory.Exists(cacheDir))
                return null;

            try
            {
                var fp = Compute();
                var path = Path.Combine(cacheDir, fp);
                if (File.Exists(path))
                {
                    // Cloudflare can serve a 403 HTML page that Steam caches at the
                    // expected fingerprint slot; reject anything that doesn't decrypt
                    // and zlib-inflate to an MZ-prefixed payload, otherwise the
                    // patcher hits "input data is not a complete block" downstream.
                    if (ValidatePayloadCache(path))
                    {
                        if (verbose) log?.Invoke($"Cache: {path}");
                        return path;
                    }
                    if (verbose) log?.Invoke($"Cache at {path} failed validation, scanning..");
                }
                else if (verbose)
                {
                    log?.Invoke($"Fingerprint {fp} computed but no cache file there");
                }
            }
            catch (Exception ex)
            {
                if (verbose) log?.Invoke($"Fingerprint computation failed ({ex.Message}), scanning..");
            }

            foreach (var f in Directory.GetFiles(cacheDir))
            {
                var name = Path.GetFileName(f);
                var info = new FileInfo(f);
                if (name.Length == 16 && info.Length > 500000 && info.Length < 5000000)
                {
                    // M15: Validate candidate by attempting AES decrypt + zlib decompress + MZ check
                    if (!ValidatePayloadCache(f))
                    {
                        if (verbose) log?.Invoke($"Cache candidate {name} failed validation, skipping");
                        continue;
                    }
                    if (verbose) log?.Invoke($"Cache (found by scan): {f}");
                    return f;
                }
            }

            return null;
        }

        public static string GetExpectedCachePath(string steamPath)
        {
            var cacheDir = Path.Combine(steamPath, "appcache", "httpcache", "3b");
            var fp = Compute();
            return Path.Combine(cacheDir, fp);
        }

        public static string ComputeFingerprint() => Compute();

        public static bool ValidatePayloadFile(string path) => ValidatePayloadCache(path);

        /// <summary>
        /// Validates a candidate cache file by attempting AES-CBC decrypt,
        /// zlib decompress, and checking for an MZ header in the result.
        /// </summary>
        static bool ValidatePayloadCache(string path)
        {
            ReadOnlySpan<byte> aesKey = SteamToolsCrypto.AesKey;

            try
            {
                byte[] raw;
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    raw = new byte[fs.Length];
                    fs.ReadExactly(raw);
                }

                if (raw.Length < 32) return false;

                var iv = raw.AsSpan(0, 16).ToArray();
                var ct = raw.AsSpan(16).ToArray();

                var plain = PayloadCrypto.AesCbcDecrypt(ct, aesKey.ToArray(), iv);

                if (plain.Length < 6) return false;

                // Payload format: 4-byte prefix then zlib data
                using var zIn = new ZLibStream(
                    new MemoryStream(plain, 4, plain.Length - 4),
                    CompressionMode.Decompress);
                var header = new byte[2];
                int read = zIn.ReadAtLeast(header, 2, throwOnEndOfStream: false);
                if (read < 2) return false;

                // Check MZ header
                return header[0] == 0x4D && header[1] == 0x5A; // 'M', 'Z'
            }
            catch
            {
                return false;
            }
        }

        static unsafe string Compute()
        {
            // CPUID leaf 0 -> vendor string
            CpuId(0, out uint _, out uint ebx0, out uint ecx0, out uint edx0);
            var vendorBytes = new byte[12];
            BitConverter.TryWriteBytes(vendorBytes.AsSpan(0, 4), ebx0);
            BitConverter.TryWriteBytes(vendorBytes.AsSpan(4, 4), edx0);
            BitConverter.TryWriteBytes(vendorBytes.AsSpan(8, 4), ecx0);
            var vendor = System.Text.Encoding.ASCII.GetString(vendorBytes);

            // CPUID leaf 1 -> family/model
            // NOTE (M14): Only the base family/model nibbles are used (not extended family/model).
            // This matches SteamTools' Core.dll fingerprint algorithm exactly.
            // Changing this would produce a different fingerprint and break cache lookup.
            CpuId(1, out uint eax1, out _, out _, out _);
            int family = ((int)eax1 >> 8) & 0xF;
            int model = ((int)eax1 >> 4) & 0xF;
            int nproc = Environment.ProcessorCount & 0xFF;

            var tag = System.Text.Encoding.ASCII.GetBytes(
                $"V{vendor}_F{family:X}_M{model:X}_C{nproc:X}");

            // XOR with "version" (same as Core.dll)
            var xorKey = System.Text.Encoding.ASCII.GetBytes("version");
            var xored = new byte[tag.Length];
            for (int i = 0; i < tag.Length; i++)
                xored[i] = (byte)(tag[i] ^ xorKey[i % 7]);

            var md5Hex = System.Text.Encoding.ASCII.GetBytes(
                Convert.ToHexString(MD5.HashData(xored)).ToLowerInvariant());

            // CRC-64 — non-standard variant (XOR-before-shift).
            // NOTE (M15): The polynomial 0x85E1C3D753D46D27 and the XOR-before-shift
            // order are specific to SteamTools' implementation. This is NOT a standard
            // CRC-64/ECMA or CRC-64/ISO algorithm. Do not "fix" the bit ordering —
            // it must match Core.dll's computation exactly.
            ulong crc = 0xFFFFFFFFFFFFFFFF;
            foreach (byte b in md5Hex)
            {
                crc ^= b;
                for (int j = 0; j < 8; j++)
                {
                    if ((crc & 1) != 0) crc ^= 0x85E1C3D753D46D27;
                    crc >>= 1;
                }
            }
            return (crc ^ 0xFFFFFFFFFFFFFFFF).ToString("X16");
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size, uint type, uint protect);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool VirtualFree(IntPtr addr, UIntPtr size, uint type);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool VirtualProtect(IntPtr addr, UIntPtr size, uint newProtect, out uint oldProtect);

        static unsafe void CpuId(uint leaf, out uint eax, out uint ebx, out uint ecx, out uint edx)
        {
            // x64 shellcode for cpuid instruction
            ReadOnlySpan<byte> code = new byte[]
            {
                0x53, 0x49, 0x89, 0xD0, 0x89, 0xC8, 0x31, 0xC9, 0x0F, 0xA2,
                0x41, 0x89, 0x00, 0x41, 0x89, 0x58, 0x04, 0x41, 0x89, 0x48,
                0x08, 0x41, 0x89, 0x50, 0x0C, 0x5B, 0xC3
            };

            var mem = VirtualAlloc(IntPtr.Zero, (UIntPtr)code.Length, 0x3000, 0x04); // PAGE_READWRITE
            if (mem == IntPtr.Zero) throw new InvalidOperationException("VirtualAlloc failed");

            try
            {
                Marshal.Copy(code.ToArray(), 0, mem, code.Length);

                if (!VirtualProtect(mem, (UIntPtr)code.Length, 0x20, out _)) // PAGE_EXECUTE_READ
                    throw new InvalidOperationException("VirtualProtect failed");
                var regs = stackalloc uint[4];

                var fn = (delegate* unmanaged[Cdecl]<uint, uint*, void>)mem;
                fn(leaf, regs);

                eax = regs[0]; ebx = regs[1]; ecx = regs[2]; edx = regs[3];
            }
            finally
            {
                VirtualFree(mem, UIntPtr.Zero, 0x8000);
            }
        }
    }
}
