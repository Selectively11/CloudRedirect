using System;
using System.IO;
using System.Text;
using System.Text.Json;

namespace CloudRedirect.Services;

// Persists app mode to settings.json + DLL pin config.
public static class ModeService
{
    // Writes both files; rolls back settings.json if pin-config write fails.
    public static void PersistMode(string mode, bool cloudRedirectEnabled)
    {
        var settingsPath = GetSettingsPath();
        byte[]? settingsBackup = File.Exists(settingsPath)
            ? TryReadAllBytes(settingsPath)
            : null;

        SaveModeSetting(mode);
        try
        {
            SetDllCloudRedirect(cloudRedirectEnabled);
        }
        catch
        {
            RestoreSettingsBackup(settingsPath, settingsBackup);
            throw;
        }
    }

    // One-time consent gate; not shown again on later mode switches.
    public static bool HasAcceptedDisclaimer()
    {
        var existing = ReadObjectOrDefault(GetSettingsPath(), skipComments: false);
        return existing.ValueKind == JsonValueKind.Object
            && existing.TryGetProperty("disclaimer_accepted", out var p)
            && p.ValueKind == JsonValueKind.True;
    }

    public static void MarkDisclaimerAccepted()
    {
        var path = GetSettingsPath();
        var dir = Path.GetDirectoryName(path)!;
        if (!Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        JsonElement existing = ReadObjectOrDefault(path, skipComments: false);

        using var ms = new MemoryStream();
        using (var writer = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            writer.WriteBoolean("disclaimer_accepted", true);
            CopyExcept(existing, "disclaimer_accepted", writer);
            writer.WriteEndObject();
        }

        FileUtils.AtomicWriteAllText(path, Encoding.UTF8.GetString(ms.ToArray()));
    }

    private static byte[]? TryReadAllBytes(string path)
    {
        try { return File.ReadAllBytes(path); }
        catch { return null; }
    }

    private static void RestoreSettingsBackup(string path, byte[]? backup)
    {
        try
        {
            if (backup != null)
                FileUtils.AtomicWriteAllBytes(path, backup);
            else if (File.Exists(path))
                File.Delete(path); // No prior file -> undo our creation.
        }
        catch { /* best-effort; caller is already surfacing an error */ }
    }

    private static void SaveModeSetting(string mode)
    {
        var path = GetSettingsPath();
        var dir = Path.GetDirectoryName(path)!;
        if (!Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        // Corrupt existing file is treated as empty; other failures propagate.
        JsonElement existing = ReadObjectOrDefault(path, skipComments: false);

        using var ms = new MemoryStream();
        using (var writer = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            writer.WriteString("mode", mode);
            CopyExcept(existing, "mode", writer);
            writer.WriteEndObject();
        }

        FileUtils.AtomicWriteAllText(path, Encoding.UTF8.GetString(ms.ToArray()));
    }

    // Writes client_type to settings.json, preserving other keys.
    public static void SaveClientType(string clientType)
    {
        var path = GetSettingsPath();
        var dir = Path.GetDirectoryName(path)!;
        if (!Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        JsonElement existing = ReadObjectOrDefault(path, skipComments: false);

        using var ms = new MemoryStream();
        using (var writer = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            writer.WriteString("client_type", clientType);
            CopyExcept(existing, "client_type", writer);
            writer.WriteEndObject();
        }

        FileUtils.AtomicWriteAllText(path, Encoding.UTF8.GetString(ms.ToArray()));
    }

    private static void SetDllCloudRedirect(bool enabled)
    {
        var path = SteamDetector.GetPinConfigPath();
        if (path == null) return;

        JsonElement existing = ReadObjectOrDefault(path, skipComments: true);

        using var ms = new MemoryStream();
        using (var writer = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            writer.WriteBoolean("cloud_redirect", enabled);
            CopyExcept(existing, "cloud_redirect", writer);
            writer.WriteEndObject();
        }

        var dir = Path.GetDirectoryName(path)!;
        if (!Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        FileUtils.AtomicWriteAllText(path, Encoding.UTF8.GetString(ms.ToArray()));
    }

    private static JsonElement ReadObjectOrDefault(string path, bool skipComments)
    {
        if (!File.Exists(path)) return default;
        try
        {
            var json = File.ReadAllText(path);
            var opts = skipComments
                ? new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip }
                : default;
            using var doc = JsonDocument.Parse(json, opts);
            return doc.RootElement.Clone();
        }
        catch { return default; }
    }

    private static void CopyExcept(JsonElement obj, string skipKey, Utf8JsonWriter writer)
    {
        if (obj.ValueKind != JsonValueKind.Object) return;
        foreach (var prop in obj.EnumerateObject())
        {
            if (prop.Name == skipKey) continue;
            prop.WriteTo(writer);
        }
    }

    private static string GetSettingsPath()
    {
        return Path.Combine(SteamDetector.GetConfigDir(), "settings.json");
    }
}
