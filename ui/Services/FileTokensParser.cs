using System.IO;

namespace CloudRedirect.Services;

/// <summary>
/// Parser for the DLL's <c>file_tokens.dat</c> format.
///
/// Format (mirrors <c>src/local_storage.cpp</c> SaveFileTokens/LoadFileTokens
/// at lines 1881-1923): one entry per line as "cleanName\ttoken\n". Empty
/// lines are skipped; lines without a tab are skipped; CRLF line endings are
/// tolerated. Filenames are stored verbatim (no canonicalization at this
/// layer) and compared case-sensitively -- mirrors the native
/// std::unordered_map&lt;std::string,...&gt; keying.
///
/// This parser is read-only and never touches disk beyond
/// <see cref="ReadFromDisk"/>; the DLL is the sole writer of the file.
/// </summary>
internal static class FileTokensParser
{
    /// <summary>
    /// Parse the raw content of <c>file_tokens.dat</c> and return the set of
    /// referenced filenames. Malformed lines are silently skipped to match
    /// the native loader's permissive behavior.
    /// </summary>
    public static HashSet<string> ParseContent(string? content)
    {
        var result = new HashSet<string>(StringComparer.Ordinal);
        if (string.IsNullOrEmpty(content)) return result;

        foreach (var rawLine in content.Split('\n'))
        {
            // Strip trailing CR(LF) per the native loader.
            var line = rawLine.TrimEnd('\r', '\n');
            if (line.Length == 0) continue;

            // Require a tab AND a non-empty name before it. Native code
            // rejects both the "no tab" case (line.find('\t') == npos) and
            // the "empty filename" case (cleanName.empty()).
            var tab = line.IndexOf('\t');
            if (tab <= 0) continue;

            result.Add(line.Substring(0, tab));
        }
        return result;
    }

    /// <summary>
    /// Read <c>file_tokens.dat</c> from disk and return the set of referenced
    /// filenames. Returns an empty set if the file does not exist. The DLL
    /// may hold the file open briefly while writing; callers that need to
    /// tolerate that should wrap this in try/catch for
    /// <see cref="IOException"/>.
    /// </summary>
    public static HashSet<string> ReadFromDisk(string path)
    {
        if (!File.Exists(path)) return new HashSet<string>(StringComparer.Ordinal);
        return ParseContent(File.ReadAllText(path));
    }
}
