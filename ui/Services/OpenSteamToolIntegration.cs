using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace CloudRedirect.Services;

public static class OpenSteamToolIntegration
{
    public enum ChangeKind
    {
        AlreadyEnabled,
        Updated,
        Created,
    }

    public sealed record EnableResult(
        ChangeKind Change,
        string ConfigPath,
        string? BackupPath);

    private static readonly Regex SectionHeader = new(
        @"^\s*\[[^\]]+\]\s*(?:#.*)?$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex CloudHeader = new(
        @"^(?<indent>\s*)\[\s*cloud\s*\](?<suffix>\s*(?:#.*)?)$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex EnabledAssignment = new(
        @"^(?<indent>\s*)enabled(?<separator>\s*=\s*)(?<value>true|false)(?<suffix>\s*(?:#.*)?)$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    private static readonly Regex AnyEnabledAssignment = new(
        @"^\s*enabled\s*=",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    public static EnableResult EnsureCloudEnabled(string steamPath)
    {
        if (string.IsNullOrWhiteSpace(steamPath))
            throw new ArgumentException("Steam path is required.", nameof(steamPath));

        var configPath = Path.Combine(steamPath, "opensteamtool.toml");
        bool existed = File.Exists(configPath);
        string original = existed ? File.ReadAllText(configPath) : string.Empty;
        string newline = original.Contains("\r\n", StringComparison.Ordinal) ? "\r\n" : "\n";

        var lines = new List<string>(Regex.Split(original, "\r\n|\n|\r"));
        bool changed = false;
        int cloudHeaderIndex = -1;

        for (int i = 0; i < lines.Count; i++)
        {
            var match = CloudHeader.Match(lines[i]);
            if (!match.Success)
                continue;

            if (cloudHeaderIndex >= 0)
                throw new InvalidDataException(
                    "opensteamtool.toml contains more than one [cloud] section.");

            cloudHeaderIndex = i;

            string canonical = match.Groups["indent"].Value + "[cloud]" +
                               match.Groups["suffix"].Value;
            if (!string.Equals(lines[i], canonical, StringComparison.Ordinal))
            {
                lines[i] = canonical;
                changed = true;
            }
        }

        if (cloudHeaderIndex < 0)
        {
            AppendCloudSection(lines);
            changed = true;
        }
        else
        {
            int sectionEnd = lines.Count;
            for (int i = cloudHeaderIndex + 1; i < lines.Count; i++)
            {
                if (SectionHeader.IsMatch(lines[i]))
                {
                    sectionEnd = i;
                    break;
                }
            }

            int enabledIndex = -1;
            Match? enabledMatch = null;
            for (int i = cloudHeaderIndex + 1; i < sectionEnd; i++)
            {
                var match = EnabledAssignment.Match(lines[i]);
                if (match.Success)
                {
                    if (enabledIndex >= 0)
                        throw new InvalidDataException(
                            "The [cloud] section contains duplicate enabled settings.");
                    enabledIndex = i;
                    enabledMatch = match;
                }
                else if (AnyEnabledAssignment.IsMatch(lines[i]))
                {
                    throw new InvalidDataException(
                        "The [cloud].enabled setting must be true or false.");
                }
            }

            if (enabledIndex < 0)
            {
                lines.Insert(cloudHeaderIndex + 1, "enabled = true");
                changed = true;
            }
            else if (!string.Equals(enabledMatch!.Groups["value"].Value, "true",
                                    StringComparison.OrdinalIgnoreCase))
            {
                lines[enabledIndex] = enabledMatch.Groups["indent"].Value + "enabled" +
                                      enabledMatch.Groups["separator"].Value + "true" +
                                      enabledMatch.Groups["suffix"].Value;
                changed = true;
            }
        }

        if (!changed)
            return new EnableResult(ChangeKind.AlreadyEnabled, configPath, null);

        string? backupPath = null;
        if (existed)
        {
            backupPath = configPath + ".cloudredirect.bak";
            if (!File.Exists(backupPath))
                FileUtils.AtomicCopy(configPath, backupPath);
        }
        else
        {
            Directory.CreateDirectory(steamPath);
        }

        FileUtils.AtomicWriteAllText(configPath, string.Join(newline, lines));
        return new EnableResult(existed ? ChangeKind.Updated : ChangeKind.Created,
                                configPath, backupPath);
    }

    private static void AppendCloudSection(List<string> lines)
    {
        if (lines.Count == 1 && lines[0].Length == 0)
        {
            lines.Clear();
        }
        else if (lines.Count > 0 && lines[^1].Length != 0)
        {
            lines.Add(string.Empty);
        }

        lines.Add("[cloud]");
        lines.Add("enabled = true");
        lines.Add(string.Empty);
    }
}
