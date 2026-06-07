using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace CloudRedirect.Services;

/// <summary>
/// Parses Steam's UserGameStatsSchema_&lt;appId&gt;.bin (a binary-KV tree) to map
/// each achievement (statId, bit) to its human-readable English display name.
///
/// Read locally from appcache\stats so the UI can show real achievement names
/// immediately, without waiting for the DLL to re-import on the next launch.
///
/// Schema tree shape:
///   &lt;appId&gt; (SECTION)
///     stats (SECTION)
///       &lt;statId&gt; (SECTION)
///         bits (SECTION)
///           &lt;bit&gt; (SECTION)
///             name "ACHIEVEMENT_x"                      (api name, fallback)
///             display (SECTION) &gt; name (SECTION) &gt; english "Human Name"
/// </summary>
internal static class AchievementSchema
{
    private const byte BKV_SECTION = 0x00;
    private const byte BKV_STRING  = 0x01;
    private const byte BKV_INT     = 0x02;
    private const byte BKV_FLOAT   = 0x03;
    private const byte BKV_UINT64  = 0x07;
    private const byte BKV_END     = 0x08;
    private const byte BKV_INT64   = 0x0A;

    private const int MaxDepth = 128;

    private sealed class Node
    {
        public byte Type;
        public string Name = "";
        public string StrVal = "";
        public List<Node> Children = new();
    }

    /// <summary>
    /// Returns (statId, bit) -> display name for the given app, or an empty map
    /// if the schema is missing/unreadable. Key = ((ulong)statId &lt;&lt; 32) | bit.
    /// </summary>
    public static Dictionary<ulong, string> LoadNames(uint appId)
    {
        var result = new Dictionary<ulong, string>();
        try
        {
            var steamPath = SteamDetector.FindSteamPath();
            if (steamPath == null) return result;

            var path = Path.Combine(steamPath, "appcache", "stats",
                $"UserGameStatsSchema_{appId}.bin");
            if (!File.Exists(path)) return result;

            var data = File.ReadAllBytes(path);
            int pos = 0;
            var root = ParseSection(data, ref pos, 0);

            // Root holds one <appId> section; descend to "stats".
            Node? statsSec = null;
            foreach (var top in root)
            {
                var s = Find(top.Children, "stats");
                if (s != null) { statsSec = s; break; }
                if (top.Name == "stats") { statsSec = top; break; }
            }
            if (statsSec == null) return result;

            foreach (var stat in statsSec.Children)
            {
                if (stat.Type != BKV_SECTION || !uint.TryParse(stat.Name, out var statId)) continue;
                var bits = Find(stat.Children, "bits");
                if (bits == null) continue;

                foreach (var bitSec in bits.Children)
                {
                    if (bitSec.Type != BKV_SECTION || !uint.TryParse(bitSec.Name, out var bit) || bit >= 32)
                        continue;

                    string display = "";
                    var disp = Find(bitSec.Children, "display");
                    if (disp != null)
                    {
                        var nameSec = Find(disp.Children, "name");
                        if (nameSec != null)
                        {
                            var eng = Find(nameSec.Children, "english");
                            if (eng != null) display = eng.StrVal;
                            if (string.IsNullOrEmpty(display) && nameSec.Children.Count > 0)
                                display = nameSec.Children[0].StrVal; // first localized as fallback
                        }
                    }
                    if (string.IsNullOrEmpty(display))
                    {
                        var apiName = Find(bitSec.Children, "name");
                        if (apiName != null) display = apiName.StrVal;
                    }

                    if (!string.IsNullOrEmpty(display))
                        result[((ulong)statId << 32) | bit] = display;
                }
            }
        }
        catch { }
        return result;
    }

    private static Node? Find(List<Node> nodes, string name)
    {
        foreach (var n in nodes)
            if (n.Name == name) return n;
        return null;
    }

    private static List<Node> ParseSection(byte[] data, ref int pos, int depth)
    {
        var nodes = new List<Node>();
        if (depth > MaxDepth) return nodes;

        while (pos < data.Length)
        {
            byte tag = data[pos++];
            if (tag == BKV_END) return nodes;

            var node = new Node { Type = tag, Name = ReadCString(data, ref pos) };

            switch (tag)
            {
                case BKV_SECTION:
                    node.Children = ParseSection(data, ref pos, depth + 1);
                    break;
                case BKV_STRING:
                    node.StrVal = ReadCString(data, ref pos);
                    break;
                case BKV_INT:
                case BKV_FLOAT:
                    pos += 4;
                    break;
                case BKV_UINT64:
                case BKV_INT64:
                    pos += 8;
                    break;
                default:
                    return nodes; // unknown tag: stop
            }
            nodes.Add(node);
        }
        return nodes;
    }

    private static string ReadCString(byte[] data, ref int pos)
    {
        int start = pos;
        while (pos < data.Length && data[pos] != 0) pos++;
        var s = Encoding.UTF8.GetString(data, start, pos - start);
        if (pos < data.Length) pos++; // skip NUL
        return s;
    }
}
