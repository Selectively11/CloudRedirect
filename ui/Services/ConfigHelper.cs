using System.IO;
using System.Text.Json;

namespace CloudRedirect.Services;

/// <summary>
/// Read-modify-write helper for the DLL config.json.
/// Preserves keys not owned by the caller, avoiding silent data loss
/// when multiple pages write different subsets of the config.
/// </summary>
public static class ConfigHelper
{
    /// <summary>
    /// Read existing config, preserve keys not in <paramref name="skipKeys"/>,
    /// let the caller write its own keys via <paramref name="writeKeys"/>,
    /// then atomic-write the result.
    /// </summary>
    public static void SaveConfig(string configPath,
                                  string[] skipKeys,
                                  System.Action<Utf8JsonWriter> writeKeys)
    {
        var dir = Path.GetDirectoryName(configPath)!;
        if (!Directory.Exists(dir))
            Directory.CreateDirectory(dir);

        JsonElement existing = default;
        if (File.Exists(configPath))
        {
            try
            {
                var oldJson = File.ReadAllText(configPath);
                using var oldDoc = JsonDocument.Parse(oldJson);
                existing = oldDoc.RootElement.Clone();
            }
            catch { }
        }

        var skipSet = new System.Collections.Generic.HashSet<string>(skipKeys);

        using var ms = new MemoryStream();
        using (var writer = new Utf8JsonWriter(ms, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();

            writeKeys(writer);

            if (existing.ValueKind == JsonValueKind.Object)
            {
                foreach (var prop in existing.EnumerateObject())
                {
                    if (skipSet.Contains(prop.Name)) continue;
                    prop.WriteTo(writer);
                }
            }

            writer.WriteEndObject();
        }

        var json = System.Text.Encoding.UTF8.GetString(ms.ToArray());
        FileUtils.AtomicWriteAllText(configPath, json);
    }
}
