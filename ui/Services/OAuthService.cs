using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CloudRedirect.Resources;

namespace CloudRedirect.Services;

/// <summary>
/// DPAPI-based token file I/O.  Compatible with the C++ DLL's dpapi_util.h:
///  - Write: JSON -> DPAPI encrypt (CurrentUser) -> binary file (atomic tmp+rename)
///  - Read:  binary file -> try DPAPI decrypt; if the first byte is '{' treat as
///    legacy plaintext JSON and silently re-encrypt in place.
/// </summary>
internal static class TokenFile
{
    public static string? ReadJson(string path)
    {
        if (!File.Exists(path)) return null;
        var raw = File.ReadAllBytes(path);
        if (raw.Length == 0) return null;

        // Legacy plaintext JSON starts with '{'
        if (raw[0] == (byte)'{')
        {
            var json = Encoding.UTF8.GetString(raw);
            // Silently upgrade to DPAPI
            try { WriteJson(path, json); } catch { /* best-effort */ }
            return json;
        }

        // DPAPI-encrypted blob
        try
        {
            var plain = ProtectedData.Unprotect(raw, null, DataProtectionScope.CurrentUser);
            return Encoding.UTF8.GetString(plain);
        }
        catch
        {
            return null;
        }
    }

    public static void WriteJson(string path, string json)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        var plain = Encoding.UTF8.GetBytes(json);
        var blob = ProtectedData.Protect(plain, null, DataProtectionScope.CurrentUser);

        FileUtils.AtomicWriteAllBytes(path, blob);
    }
}

/// <summary>
/// Handles OAuth2 authorization code flow for Google Drive and OneDrive.
/// Opens the user's browser, listens for the callback on localhost, exchanges
/// the auth code for tokens, and saves them in the format the DLL expects.
/// </summary>
public sealed class OAuthService : IDisposable
{
    // Google Drive (clasp credentials — same as hardcoded in the DLL)
    private const string GDriveClientId = // owo what's this?
        "1072944905499-vm2v2i5dvn0a0d2o4ca36i1vge8cvbn0.apps.googleusercontent.com";
    private const string GDriveClientSecret = "v6V3fKV_zWU7iw1DrpO1rknX"; // uwuuu
    private const string GDriveScope = "https://www.googleapis.com/auth/drive.file";
    private const string GDriveAuthUrl = "https://accounts.google.com/o/oauth2/v2/auth";
    private const string GDriveTokenUrl = "https://oauth2.googleapis.com/token";

    // OneDrive (using rclone's public client ID - our Azure AD app has redirect URI issues)
    private const string OneDriveClientId = "b15665d9-eda6-4092-8539-0eec376afd59";
    private const string OneDriveScope = "Files.ReadWrite offline_access";
    private const string OneDriveAuthUrl =
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
    private const string OneDriveTokenUrl =
        "https://login.microsoftonline.com/common/oauth2/v2.0/token";
    private const int OneDrivePort = 53682; // rclone's Azure AD app only has this port registered

    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(30) };
    private HttpListener? _listener;
    private CancellationTokenSource? _cts;
    private string? _oauthState;      // CSRF protection (Google Drive only)
    private string? _codeVerifier;    // PKCE code verifier (Google Drive only)
    private string? _currentProvider; // Track current provider for state validation

    /// <summary>
    /// Run the full OAuth flow for the given provider.
    /// Opens the browser, waits for the callback, exchanges the code, and saves tokens.
    /// </summary>
    /// <param name="provider">"gdrive" or "onedrive"</param>
    /// <param name="tokenPath">Where to save the resulting tokens.json</param>
    /// <param name="log">Progress callback</param>
    /// <param name="cancel">Cancellation token</param>
    /// <returns>True if tokens were obtained and saved successfully.</returns>
    public async Task<bool> AuthorizeAsync(
        string provider,
        string tokenPath,
        Action<string> log,
        CancellationToken cancel = default)
    {
        // Track current provider for state validation
        _currentProvider = provider;
        
        // Find an available port and start the listener
        // OneDrive uses fixed port 53682 (rclone's Azure AD app requirement)
        // Google Drive uses dynamic port
        int port = 0;
        string redirectUri;
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        _listener = new HttpListener();

        if (provider == "onedrive")
        {
            port = OneDrivePort;
            redirectUri = $"http://localhost:{port}/";
            
            log($"Starting OAuth flow for {provider}...");
            log($"Listening on {redirectUri}");

            _listener.Prefixes.Clear();
            _listener.Prefixes.Add(redirectUri);

            try
            {
                _listener.Start();
            }
            catch (HttpListenerException ex)
            {
                log($"ERROR: Failed to start HTTP listener on port {port}: {ex.Message}");
                log("(Port 53682 may be in use by another application)");
                return false;
            }
        }
        else
        {
            // Google Drive - use dynamic port with /callback path
            for (int attempt = 0; attempt < 5; attempt++)
            {
                port = FindAvailablePort();
                redirectUri = $"http://localhost:{port}/callback";

                log($"Starting OAuth flow for {provider}...");
                log($"Listening on {redirectUri}");

                _listener.Prefixes.Clear();
                _listener.Prefixes.Add($"http://localhost:{port}/callback/");

                try
                {
                    _listener.Start();
                    break; // success
                }
                catch (HttpListenerException) when (attempt < 4)
                {
                    log($"Port {port} in use, retrying...");
                    _listener.Close();
                    _listener = new HttpListener();
                    continue;
                }
                catch (HttpListenerException ex)
                {
                    log($"ERROR: Failed to start HTTP listener after 5 attempts: {ex.Message}");
                    return false;
                }
            }
        }

        string redirectUriFinal = provider == "onedrive" 
            ? $"http://localhost:{port}/" 
            : $"http://localhost:{port}/callback";

        // Generate CSRF state and PKCE code verifier (only used for Google Drive)
        _oauthState = GenerateRandomString(32);
        _codeVerifier = GenerateRandomString(64);
        string codeChallenge = ComputeCodeChallenge(_codeVerifier);

        // Build the authorization URL
        string authUrl = provider switch
        {
            "gdrive" => BuildGDriveAuthUrl(redirectUriFinal, _oauthState, codeChallenge),
            "onedrive" => BuildOneDriveAuthUrl(redirectUriFinal),
            _ => throw new ArgumentException($"Unknown provider: {provider}")
        };

        // Open browser
        log("Opening browser for authorization...");
        try
        {
            Process.Start(new ProcessStartInfo(authUrl) { UseShellExecute = true })?.Dispose();
        }
        catch (Exception ex)
        {
            log($"ERROR: Could not open browser: {ex.Message}");
            log($"Please manually open: {authUrl}");
        }

        // Wait for the callback
        string? code = null;
        try
        {
            log("Waiting for authorization (complete the sign-in in your browser)...");
            code = await WaitForCallbackAsync(_cts.Token);
        }
        catch (OperationCanceledException)
        {
            log("Authorization cancelled.");
            return false;
        }
        catch (Exception ex)
        {
            log($"ERROR: Callback failed: {ex.Message}");
            return false;
        }
        finally
        {
            StopListener();
        }

        if (string.IsNullOrEmpty(code))
        {
            log("ERROR: No authorization code received.");
            return false;
        }

        log("Authorization code received. Exchanging for tokens...");

        // Exchange code for tokens
        TokenResult? tokens;
        try
        {
            tokens = provider switch
            {
                "gdrive" => await ExchangeGDriveCodeAsync(code, redirectUriFinal, _codeVerifier!, cancel),
                "onedrive" => await ExchangeOneDriveCodeAsync(code, redirectUriFinal, cancel),
                _ => null
            };
        }
        catch (Exception ex)
        {
            log($"ERROR: Token exchange failed: {ex.Message}");
            return false;
        }

        if (tokens == null || string.IsNullOrEmpty(tokens.RefreshToken))
        {
            log("ERROR: No refresh token received. The authorization may need to be revoked and re-done.");
            return false;
        }

        // Save tokens in the format the DLL expects (DPAPI-encrypted)
        try
        {
            long expiresAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + tokens.ExpiresIn;

            var tokenObj = new
            {
                access_token = tokens.AccessToken,
                refresh_token = tokens.RefreshToken,
                expires_at = expiresAt
            };

            string json = JsonSerializer.Serialize(tokenObj, new JsonSerializerOptions
            {
                WriteIndented = true
            });

            await Task.Run(() => TokenFile.WriteJson(tokenPath, json), cancel);
            log($"Tokens saved to: {tokenPath}");
            log($"Access token expires in {tokens.ExpiresIn}s (the DLL will auto-refresh).");
            log("Authentication successful!");
            return true;
        }
        catch (Exception ex)
        {
            log($"ERROR: Failed to save tokens: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Check if a token file exists and contains a refresh token.
    /// Returns a status string for display.
    /// </summary>
    public static TokenStatus CheckTokenStatus(string tokenPath)
    {
        if (string.IsNullOrEmpty(tokenPath) || !File.Exists(tokenPath))
            return new TokenStatus(false, "No token file found");

        try
        {
            var json = TokenFile.ReadJson(tokenPath);
            if (json == null)
                return new TokenStatus(false, "Cannot decrypt token file");

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            bool hasRefresh = root.TryGetProperty("refresh_token", out var rt)
                              && rt.GetString()?.Length > 0;

            if (!hasRefresh)
                return new TokenStatus(false, "Token file exists but missing refresh token");

            return new TokenStatus(true, "Authenticated.");
        }
        catch (Exception ex)
        {
            return new TokenStatus(false, $"Cannot read token file: {ex.Message}");
        }
    }

    // --- private helpers ---

    private static string BuildGDriveAuthUrl(string redirectUri, string state, string codeChallenge)
    {
        return $"{GDriveAuthUrl}" +
               $"?client_id={Uri.EscapeDataString(GDriveClientId)}" +
               $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
               $"&response_type=code" +
               $"&scope={Uri.EscapeDataString(GDriveScope)}" +
               $"&access_type=offline" +
               $"&prompt=consent" +
               $"&state={Uri.EscapeDataString(state)}" +
               $"&code_challenge={Uri.EscapeDataString(codeChallenge)}" +
               $"&code_challenge_method=S256";
    }

    private static string BuildOneDriveAuthUrl(string redirectUri)
    {
        // OneDrive with rclone's client ID: no PKCE, no state
        return $"{OneDriveAuthUrl}" +
               $"?client_id={Uri.EscapeDataString(OneDriveClientId)}" +
               $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
               $"&response_type=code" +
               $"&scope={Uri.EscapeDataString(OneDriveScope)}" +
               $"&prompt=consent";
    }

    private async Task<string?> WaitForCallbackAsync(CancellationToken cancel)
    {
        // Wait up to 5 minutes for the user to complete auth
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancel, timeout.Token);

        // Loop to skip non-OAuth requests (browser favicon, preflight, etc.)
        while (true)
        {
            var ctx = await _listener!.GetContextAsync().WaitAsync(linked.Token);
            var query = ctx.Request.QueryString;
            string? code = query["code"];
            string? error = query["error"];
            string? state = query["state"];

            // If this request has neither code nor error nor state, it's not the OAuth
            // callback (e.g. favicon.ico request). Send a minimal response and loop.
            if (string.IsNullOrEmpty(code) && string.IsNullOrEmpty(error) && string.IsNullOrEmpty(state))
            {
                ctx.Response.StatusCode = 204;
                ctx.Response.Close();
                continue;
            }

            // Validate CSRF state parameter (Google Drive only - OneDrive doesn't use state)
            if (_currentProvider != "onedrive" && _oauthState != null && state != _oauthState)
            {
                error = "state_mismatch";
                code = null;
            }

        // Send a response to the browser
        string html;
        if (!string.IsNullOrEmpty(code))
        {
            html = $"""
                <html><body style="font-family:Segoe UI,sans-serif;text-align:center;padding:60px;background:#1e1e1e;color:#fff">
                <h1>{System.Net.WebUtility.HtmlEncode(S.Get("OAuth_AuthSuccessTitle"))}</h1>
                <p>{System.Net.WebUtility.HtmlEncode(S.Get("OAuth_AuthSuccessBody"))}</p>
                </body></html>
                """;
        }
        else
        {
            html = $"""
                <html><body style="font-family:Segoe UI,sans-serif;text-align:center;padding:60px;background:#1e1e1e;color:#fff">
                <h1>{System.Net.WebUtility.HtmlEncode(S.Get("OAuth_AuthFailedTitle"))}</h1>
                <p>Error: {System.Net.WebUtility.HtmlEncode(error ?? "unknown")}</p>
                <p>{System.Net.WebUtility.HtmlEncode(S.Get("OAuth_AuthFailedBody"))}</p>
                </body></html>
                """;
        }

        byte[] buf = Encoding.UTF8.GetBytes(html);
        ctx.Response.ContentType = "text/html; charset=utf-8";
        ctx.Response.ContentLength64 = buf.Length;
        await ctx.Response.OutputStream.WriteAsync(buf, linked.Token);
        ctx.Response.Close();

        return code;
        } // end while
    }

    private async Task<TokenResult?> ExchangeGDriveCodeAsync(
        string code, string redirectUri, string codeVerifier, CancellationToken cancel)
    {
        var body = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["code"] = code,
            ["client_id"] = GDriveClientId,
            ["client_secret"] = GDriveClientSecret,
            ["redirect_uri"] = redirectUri,
            ["grant_type"] = "authorization_code",
            ["code_verifier"] = codeVerifier
        });

        var resp = await _http.PostAsync(GDriveTokenUrl, body, cancel);
        var json = await resp.Content.ReadAsStringAsync(cancel);

        if (!resp.IsSuccessStatusCode)
            throw new Exception($"Token exchange failed (HTTP {(int)resp.StatusCode}): {json}");

        return ParseTokenResponse(json);
    }

    private async Task<TokenResult?> ExchangeOneDriveCodeAsync(
        string code, string redirectUri, CancellationToken cancel)
    {
        // OneDrive with rclone's client ID: no PKCE code_verifier
        var body = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["code"] = code,
            ["client_id"] = OneDriveClientId,
            ["redirect_uri"] = redirectUri,
            ["grant_type"] = "authorization_code",
            ["scope"] = OneDriveScope
        });

        var resp = await _http.PostAsync(OneDriveTokenUrl, body, cancel);
        var json = await resp.Content.ReadAsStringAsync(cancel);

        if (!resp.IsSuccessStatusCode)
            throw new Exception($"Token exchange failed (HTTP {(int)resp.StatusCode}): {json}");

        return ParseTokenResponse(json);
    }

    private static TokenResult ParseTokenResponse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        return new TokenResult
        {
            AccessToken = root.TryGetProperty("access_token", out var at) ? at.GetString() ?? "" : "",
            RefreshToken = root.TryGetProperty("refresh_token", out var rt) ? rt.GetString() ?? "" : "",
            ExpiresIn = root.TryGetProperty("expires_in", out var ei) ? ei.GetInt64() : 3600
        };
    }

    private static string GenerateRandomString(int length)
    {
        var bytes = RandomNumberGenerator.GetBytes(length);
        return Convert.ToBase64String(bytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "")
            .Substring(0, length);
    }

    private static string ComputeCodeChallenge(string codeVerifier)
    {
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier));
        return Convert.ToBase64String(hash)
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "");
    }

    private static int FindAvailablePort()
    {
        // Use port 0 to let the OS pick an available port.
        // Start and immediately stop — the port is very likely still free
        // for the HttpListener that follows (same-process, localhost only).
        var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        try
        {
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            return port;
        }
        finally
        {
            listener.Stop();
        }
    }

    private void StopListener()
    {
        try { _listener?.Stop(); } catch { }
        try { _listener?.Close(); } catch { }
        _listener = null;
    }

    public void Dispose()
    {
        StopListener();
        _cts?.Dispose();
        _http.Dispose();
    }
}

public record TokenStatus(bool IsAuthenticated, string Message);

public record TokenResult
{
    public string AccessToken { get; init; } = "";
    public string RefreshToken { get; init; } = "";
    public long ExpiresIn { get; init; }
}
