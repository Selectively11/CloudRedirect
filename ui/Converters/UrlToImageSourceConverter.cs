using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media.Imaging;
using CloudRedirect.Services;

namespace CloudRedirect.Converters;

/// <summary>
/// Converts a string URL (Steam CDN <c>https://</c> or a <c>file://</c> path
/// pointing at our on-disk artwork cache) into a <see cref="BitmapImage"/> for
/// declarative binding from XAML.
///
/// <para>
/// The converter deliberately behaves differently for the two URI schemes:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <b>file://</b> -- decoded with <see cref="BitmapCacheOption.OnLoad"/>
///     and <see cref="System.Windows.Freezable.Freeze"/>d. OnLoad decodes
///     immediately and releases the backing file handle; without it the cached
///     JPEG stays locked for the lifetime of the BitmapImage, blocking both
///     the eviction sweep in <see cref="SteamStoreClient"/> and the
///     <c>File.Move(overwrite: true)</c> that installs a refreshed asset on
///     CDN hash rotation. Freezing makes the bitmap safe to share across
///     bindings without per-access dispatcher marshalling.
///   </description></item>
///   <item><description>
///     <b>https://</b> -- created with WPF's default
///     (<see cref="BitmapCacheOption.Default"/>) streaming async load and
///     left unfrozen. Setting <c>OnLoad</c> here would force a synchronous
///     UI-thread download that (a) stalls rendering when dozens of app cards
///     materialize at once and (b) silently failed often enough in practice
///     that images wouldn't appear on first paint (cold cache &#8594; HeaderUrl
///     is still the CDN URL at that point; only the second visit sees the
///     file:// rewrite). Matching the pre-converter default behavior means
///     first-visit images progressively appear as the CDN responds, and the
///     ensuing background download still lands in the disk cache for the
///     next launch.
///   </description></item>
/// </list>
///
/// <para>Behavior contract:</para>
/// <list type="bullet">
///   <item><description>
///     Null / empty / non-string / non-URI inputs return
///     <see cref="Binding.DoNothing"/> so the target property keeps its
///     design-time or template-default value. Returning <c>null</c> would
///     clear an <see cref="System.Windows.Media.ImageBrush.ImageSource"/>
///     that was set by another trigger.
///   </description></item>
///   <item><description>
///     The URL is validated through
///     <see cref="SteamStoreClient.IsValidImageUrl"/>, which path-traversal-
///     guards <c>file://</c> inputs against the artwork cache directory.
///     Anything rejected by that gate returns <see cref="Binding.DoNothing"/>.
///   </description></item>
///   <item><description>
///     No fallback image is produced. A failed decode returns
///     <see cref="Binding.DoNothing"/> and lets the caller surface a
///     template-level placeholder.
///   </description></item>
/// </list>
/// </summary>
public sealed class UrlToImageSourceConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is not string url || string.IsNullOrWhiteSpace(url))
            return Binding.DoNothing;

        if (!SteamStoreClient.IsValidImageUrl(url))
            return Binding.DoNothing;

        Uri uri;
        try
        {
            uri = new Uri(url);
        }
        catch
        {
            return Binding.DoNothing;
        }

        try
        {
            var bitmap = new BitmapImage();
            bitmap.BeginInit();
            if (uri.IsFile)
            {
                // Local cache file: decode now, release the handle, freeze so
                // eviction + atomic File.Move(overwrite: true) aren't blocked.
                bitmap.CacheOption = BitmapCacheOption.OnLoad;
            }
            // HTTP: leave CacheOption at Default so the download streams in
            // the background. Intentionally NOT frozen -- an unfinished
            // async-loading BitmapImage is not yet in a freezable state, and
            // freezing would throw.
            bitmap.UriSource = uri;
            bitmap.EndInit();
            if (uri.IsFile)
                bitmap.Freeze();
            return bitmap;
        }
        catch
        {
            return Binding.DoNothing;
        }
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
