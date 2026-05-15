using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace CloudRedirect.Services
{
    /// <summary>
    /// Represents a single AutoCloud save file rule from appinfo's UFS section.
    /// </summary>
    internal record AutoCloudRule(
        string Root,       // e.g. "gameinstall", "WinMyDocuments", etc.
        string Path,       // e.g. "Saves", "Preferences"
        string Pattern,    // e.g. "*.bepis", "Prefs.json"
        bool Recursive     // whether to match recursively in subdirectories
    );

    /// <summary>
    /// Parsed UFS (User File System / cloud config) data for a single app.
    /// </summary>
    internal class AppCloudConfig
    {
        public uint AppId { get; set; }
        public int Quota { get; set; }
        public int MaxNumFiles { get; set; }
        public List<AutoCloudRule> SaveFiles { get; set; } = new();

        /// <summary>
        /// Resolves an AutoCloud root name to an actual filesystem path.
        /// Returns null for "gameinstall" if gameInstallDir is not provided,
        /// and null for empty/default roots (those use userdata/remote/).
        /// </summary>
        public static string? RootToFilesystemPath(string root, string? gameInstallDir = null)
        {
            if (string.IsNullOrEmpty(root)) return null; // default root = userdata/remote/

            return root.ToLowerInvariant() switch
            {
                "gameinstall" => gameInstallDir, // null if not resolved
                "winmydocuments" => Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                "winappdatalocal" => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "winappdataroaming" => Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "winappdatalocallow" => Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    "AppData", "LocalLow"),
                _ => null
            };
        }

        /// <summary>
        /// Finds a game's install directory by reading its appmanifest ACF file.
        /// Searches all Steam library folders for the app's manifest.
        /// Returns null if not found.
        /// </summary>
        public static string? FindGameInstallDir(string steamPath, uint appId)
        {
            // Check all library folders from libraryfolders.vdf
            var libraryPaths = GetLibraryFolderPaths(steamPath);
            foreach (var libPath in libraryPaths)
            {
                var manifestPath = Path.Combine(libPath, "steamapps", $"appmanifest_{appId}.acf");
                if (!File.Exists(manifestPath)) continue;

                var installDir = ParseInstallDirFromManifest(manifestPath);
                if (installDir != null)
                    return Path.Combine(libPath, "steamapps", "common", installDir);
            }
            return null;
        }

        /// <summary>
        /// Reads library folder paths from Steam's libraryfolders.vdf.
        /// Always includes the main Steam path as the first entry.
        /// </summary>
        private static List<string> GetLibraryFolderPaths(string steamPath)
        {
            var paths = new List<string> { steamPath };
            var vdfPath = Path.Combine(steamPath, "config", "libraryfolders.vdf");
            if (!File.Exists(vdfPath)) return paths;

            try
            {
                // Simple text VDF parser -- just extract "path" values
                foreach (var line in File.ReadLines(vdfPath))
                {
                    var trimmed = line.Trim();
                    if (!trimmed.StartsWith("\"path\"", StringComparison.OrdinalIgnoreCase)) continue;

                    // Format: "path"		"C:\\Games\\Steam"
                    var parts = trimmed.Split('"');
                    if (parts.Length >= 4)
                    {
                        var p = parts[3].Replace("\\\\", "\\");
                        if (Directory.Exists(p) && !paths.Contains(p, StringComparer.OrdinalIgnoreCase))
                            paths.Add(p);
                    }
                }
            }
            catch { }

            return paths;
        }

        /// <summary>
        /// Reads the "installdir" value from a Steam appmanifest ACF file.
        /// </summary>
        private static string? ParseInstallDirFromManifest(string manifestPath)
        {
            try
            {
                foreach (var line in File.ReadLines(manifestPath))
                {
                    var trimmed = line.Trim();
                    if (!trimmed.StartsWith("\"installdir\"", StringComparison.OrdinalIgnoreCase)) continue;

                    var parts = trimmed.Split('"');
                    if (parts.Length >= 4)
                        return parts[3];
                }
            }
            catch { }
            return null;
        }
    }

    /// <summary>
    /// Parses Steam's appinfo.vdf v29 binary format to extract per-app AutoCloud configuration.
    /// Format: 16-byte header, then app records, then string table at end of file.
    /// Each app record: appid(4) + size(4) + payload(size bytes).
    /// Payload: 40-byte header + 20-byte SHA1 + binary KV data.
    /// </summary>
    internal class AppInfoParser
    {
        private const uint MAGIC_V29 = 0x07564429;

        // Binary KV type codes
        private const byte KV_SECTION = 0x00;
        private const byte KV_STRING = 0x01;
        private const byte KV_INT32 = 0x02;
        private const byte KV_FLOAT = 0x03;
        private const byte KV_PTR = 0x04;
        private const byte KV_WSTRING = 0x05;
        private const byte KV_COLOR = 0x06;
        private const byte KV_UINT64 = 0x07;
        private const byte KV_END = 0x08;
        private const byte KV_END_ALT = 0x09;
        private const byte KV_INT64 = 0x0A;

        /// <summary>
        /// Parse appinfo.vdf and return AutoCloud config for all apps that have UFS/savefiles defined.
        /// </summary>
        public static Dictionary<uint, AppCloudConfig> ParseAll(string appInfoPath)
        {
            var results = new Dictionary<uint, AppCloudConfig>();

            using var fs = File.OpenRead(appInfoPath);
            using var reader = new BinaryReader(fs, Encoding.UTF8, leaveOpen: true);

            // Read header (16 bytes)
            uint magic = reader.ReadUInt32();
            if (magic != MAGIC_V29)
                throw new InvalidDataException($"Expected appinfo.vdf v29 magic 0x{MAGIC_V29:X8}, got 0x{magic:X8}");

            reader.ReadUInt32(); // universe (unused)
            ulong stringTableOffset = reader.ReadUInt64();

            // Read string table first
            var stringTable = ReadStringTable(fs, (long)stringTableOffset);

            // Now scan records
            fs.Seek(16, SeekOrigin.Begin);

            while (fs.Position < (long)stringTableOffset)
            {
                if (fs.Position + 4 > fs.Length) break;
                uint appId = reader.ReadUInt32();
                if (appId == 0) break; // end sentinel

                if (fs.Position + 4 > fs.Length) break;
                uint size = reader.ReadUInt32();

                if (size == 0 || size > int.MaxValue || fs.Position + size > fs.Length)
                    break;

                // Read payload
                byte[] payload = reader.ReadBytes((int)size);

                // Parse the KV data to extract UFS section
                // Payload layout: 40-byte header + 20-byte SHA1 + KV data
                if (payload.Length < 60) continue;

                var kvData = payload.AsSpan(60);
                var config = ParseAppKV(appId, kvData, stringTable);
                if (config != null && config.SaveFiles.Count > 0)
                {
                    results[appId] = config;
                }
            }

            return results;
        }

        /// <summary>
        /// Parse appinfo.vdf for a single specific app ID.
        /// </summary>
        public static AppCloudConfig? ParseSingle(string appInfoPath, uint targetAppId)
        {
            using var fs = File.OpenRead(appInfoPath);
            using var reader = new BinaryReader(fs, Encoding.UTF8, leaveOpen: true);

            uint magic = reader.ReadUInt32();
            if (magic != MAGIC_V29)
                throw new InvalidDataException($"Expected appinfo.vdf v29 magic 0x{MAGIC_V29:X8}, got 0x{magic:X8}");

            reader.ReadUInt32(); // universe (unused)
            ulong stringTableOffset = reader.ReadUInt64();

            var stringTable = ReadStringTable(fs, (long)stringTableOffset);

            fs.Seek(16, SeekOrigin.Begin);
            while (fs.Position < (long)stringTableOffset)
            {
                if (fs.Position + 4 > fs.Length) break;
                uint appId = reader.ReadUInt32();
                if (appId == 0) break;

                if (fs.Position + 4 > fs.Length) break;
                uint size = reader.ReadUInt32();

                if (size == 0 || fs.Position + size > fs.Length) break;

                if (appId == targetAppId)
                {
                    byte[] payload = reader.ReadBytes((int)size);
                    if (payload.Length < 60) return null;
                    var kvData = payload.AsSpan(60);
                    return ParseAppKV(appId, kvData, stringTable);
                }
                else
                {
                    fs.Seek(size, SeekOrigin.Current);
                }
            }

            return null;
        }

        private static List<string> ReadStringTable(Stream fs, long offset)
        {
            var table = new List<string>();
            fs.Seek(offset, SeekOrigin.Begin);
            using var reader = new BinaryReader(fs, Encoding.UTF8, leaveOpen: true);

            uint count = reader.ReadUInt32();
            for (uint i = 0; i < count; i++)
            {
                table.Add(ReadCString(reader));
            }
            return table;
        }

        private static string ReadCString(BinaryReader reader)
        {
            // Read null-terminated UTF-8 string with single allocation.
            // Use a stack buffer for typical short strings, heap for longer.
            Span<byte> stackBuf = stackalloc byte[256];
            int len = 0;
            while (true)
            {
                byte b = reader.ReadByte();
                if (b == 0) break;
                if (len < stackBuf.Length)
                    stackBuf[len] = b;
                else if (len == stackBuf.Length)
                {
                    // Spill to heap: copy stack portion + continue
                    var heap = new byte[stackBuf.Length * 2];
                    stackBuf.CopyTo(heap);
                    heap[len] = b;
                    len++;
                    // Continue reading into heap array, growing as needed
                    while (true)
                    {
                        byte b2 = reader.ReadByte();
                        if (b2 == 0) break;
                        if (len >= heap.Length)
                            Array.Resize(ref heap, heap.Length * 2);
                        heap[len++] = b2;
                    }
                    return Encoding.UTF8.GetString(heap, 0, len);
                }
                len++;
            }
            return Encoding.UTF8.GetString(stackBuf[..len]);
        }

        private static AppCloudConfig? ParseAppKV(uint appId, ReadOnlySpan<byte> kvData, List<string> stringTable)
        {
            int offset = 0;
            var tree = ParseBinaryKV(kvData, ref offset, stringTable);

            // Navigate to appinfo -> ufs -> savefiles
            var appInfoNode = FindChild(tree, "appinfo");
            if (appInfoNode == null) return null;

            var ufsNode = FindChild(appInfoNode.Children, "ufs");
            if (ufsNode == null) return null;

            var config = new AppCloudConfig { AppId = appId };

            // Extract quota and maxnumfiles
            var quotaNode = FindChild(ufsNode.Children, "quota");
            if (quotaNode != null && quotaNode.IntValue.HasValue)
                config.Quota = quotaNode.IntValue.Value;

            var maxNode = FindChild(ufsNode.Children, "maxnumfiles");
            if (maxNode != null && maxNode.IntValue.HasValue)
                config.MaxNumFiles = maxNode.IntValue.Value;

            // Extract savefiles
            var savefilesNode = FindChild(ufsNode.Children, "savefiles");
            if (savefilesNode != null)
            {
                foreach (var entry in savefilesNode.Children)
                {
                    if (entry.Children == null || entry.Children.Count == 0) continue;

                    string root = FindChild(entry.Children, "root")?.StringValue ?? "";
                    string path = FindChild(entry.Children, "path")?.StringValue ?? "";
                    string pattern = FindChild(entry.Children, "pattern")?.StringValue ?? "*";
                    bool recursive = (FindChild(entry.Children, "recursive")?.IntValue ?? 0) != 0;

                    config.SaveFiles.Add(new AutoCloudRule(root, path, pattern, recursive));
                }
            }

            return config;
        }

        private class KVNode
        {
            public string? Key { get; set; }
            public string? StringValue { get; set; }
            public int? IntValue { get; set; }
            public long? LongValue { get; set; }
            public List<KVNode>? Children { get; set; }
        }

        private static KVNode? FindChild(List<KVNode>? nodes, string key)
        {
            if (nodes == null) return null;
            foreach (var node in nodes)
            {
                if (string.Equals(node.Key, key, StringComparison.OrdinalIgnoreCase))
                    return node;
            }
            return null;
        }

        private const int MAX_KV_DEPTH = 64;

        private static List<KVNode> ParseBinaryKV(ReadOnlySpan<byte> data, ref int offset, List<string> stringTable, int depth = 0)
        {
            var nodes = new List<KVNode>();

            if (depth >= MAX_KV_DEPTH) return nodes;

            while (offset < data.Length)
            {
                byte typeByte = data[offset];
                offset++;

                if (typeByte == KV_END || typeByte == KV_END_ALT)
                    break;

                // Read key name from string table index
                if (offset + 4 > data.Length) break;
                uint keyIdx = BitConverter.ToUInt32(data.Slice(offset, 4));
                offset += 4;

                string keyName = keyIdx < (uint)stringTable.Count ? stringTable[(int)keyIdx] : $"<idx_{keyIdx}>";

                var node = new KVNode { Key = keyName };

                switch (typeByte)
                {
                    case KV_SECTION:
                        node.Children = ParseBinaryKV(data, ref offset, stringTable, depth + 1);
                        break;

                    case KV_STRING:
                        node.StringValue = ReadCStringFromSpan(data, ref offset);
                        break;

                    case KV_INT32:
                        if (offset + 4 <= data.Length)
                        {
                            node.IntValue = BitConverter.ToInt32(data.Slice(offset, 4));
                            offset += 4;
                        }
                        break;

                    case KV_FLOAT:
                        offset += 4;
                        break;

                    case KV_PTR:
                    case KV_COLOR:
                        offset += 4;
                        break;

                    case KV_UINT64:
                        if (offset + 8 <= data.Length)
                        {
                            node.LongValue = (long)BitConverter.ToUInt64(data.Slice(offset, 8));
                            offset += 8;
                        }
                        break;

                    case KV_INT64:
                        if (offset + 8 <= data.Length)
                        {
                            node.LongValue = BitConverter.ToInt64(data.Slice(offset, 8));
                            offset += 8;
                        }
                        break;

                    case KV_WSTRING:
                        // UTF-16 null-terminated
                        while (offset + 2 <= data.Length)
                        {
                            ushort wc = BitConverter.ToUInt16(data.Slice(offset, 2));
                            offset += 2;
                            if (wc == 0) break;
                        }
                        break;

                    default:
                        // Unknown type, bail
                        return nodes;
                }

                nodes.Add(node);
            }

            return nodes;
        }

        private static string ReadCStringFromSpan(ReadOnlySpan<byte> data, ref int offset)
        {
            int start = offset;
            while (offset < data.Length && data[offset] != 0)
                offset++;
            var str = Encoding.UTF8.GetString(data.Slice(start, offset - start));
            if (offset < data.Length) offset++; // skip null terminator
            return str;
        }
    }
}
