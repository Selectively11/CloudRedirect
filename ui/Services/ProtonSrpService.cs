using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Net.Http;
using System.Net.Http.Headers;
using CloudRedirect.Windows;
using Konscious.Security.Cryptography;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace CloudRedirect.Services;

/// <summary>
/// Authenticates to Proton using the SRP v4 protocol, then resolves drive metadata
/// and writes the extended token file the C++ DLL expects.
/// </summary>
internal static class ProtonSrpService
{
    private const string ApiBase    = "https://mail.proton.me/api";
    private const string AppVersion = "external-drive-cloudredirect@2.1.8-stable";

    public static async Task<bool> AuthorizeAsync(
        string tokenPath, Action<string> log, CancellationToken cancel)
    {
        var win = new ProtonLoginWindow
        {
            Owner = System.Windows.Application.Current.MainWindow
        };
        bool? dlgResult = null;
        await System.Windows.Application.Current.Dispatcher.InvokeAsync(() =>
        {
            dlgResult = win.ShowDialog();
        });
        if (dlgResult != true)
        {
            log("Sign-in cancelled.");
            return false;
        }

        string email    = win.Email;
        string password = win.Password;

        using var http = BuildClient();

        try
        {
            // ── Step 1: SRP challenge ─────────────────────────────────────────
            log("Requesting SRP challenge...");
            var info = await PostJsonAsync(http, "/auth/v4/info",
                $"{{\"Username\":{JsonEscape(email)},\"Intent\":\"Proton\"}}",
                cancel);

            if (GetInt(info, "Code") != 1000)
            {
                log($"ERROR: /auth/v4/info — Code {GetInt(info, "Code")}");
                return false;
            }

            int    srpVersion = GetInt(info, "Version");
            string modHex     = GetStr(info, "Modulus");
            string serverEph  = GetStr(info, "ServerEphemeral");
            string srpSalt    = GetStr(info, "Salt");
            string sessionId  = GetStr(info, "SRPSession");

            // ── Step 2: Client SRP proof ──────────────────────────────────────
            log("Computing SRP proof...");
            byte[] modBytes       = ParseSrpModulus(modHex);
            byte[] saltBytes      = FromB64(srpSalt);
            byte[] serverEphB     = FromB64(serverEph);
            byte[] hashedPassword = ExpandPassword(password, srpVersion, saltBytes, modBytes);

            var (clientEph, clientProof) = SrpCompute(modBytes, serverEphB, hashedPassword);

            // ── Step 3: Authenticate ──────────────────────────────────────────
            log("Authenticating...");
            string authBody = $"{{\"Username\":{JsonEscape(email)}," +
                              $"\"ClientEphemeral\":{JsonEscape(ToB64(clientEph))}," +
                              $"\"ClientProof\":{JsonEscape(ToB64(clientProof))}," +
                              $"\"SRPSession\":{JsonEscape(sessionId)}," +
                              $"\"Intent\":\"Proton\"}}";

            var auth = await PostJsonAsync(http, "/auth/v4", authBody, cancel);
            int authCode = GetInt(auth, "Code");
            if (authCode != 1000)
            {
                log($"ERROR: Authentication failed — Code {authCode}");
                if (authCode == 8002) log("Incorrect password.");
                return false;
            }

            string uid          = GetStr(auth, "UID");
            string accessToken  = GetStr(auth, "AccessToken");
            string refreshToken = GetStr(auth, "RefreshToken");
            long   expiresIn    = GetLong(auth, "ExpiresIn");
            long   expiresAt    = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + expiresIn;

            http.DefaultRequestHeaders.Remove("x-pm-uid");
            http.DefaultRequestHeaders.Add("x-pm-uid", uid);
            http.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", accessToken);

            // ── Step 4: Key salt ──────────────────────────────────────────────
            log("Fetching key salts...");
            var saltsResp = await GetJsonAsync(http, "/core/v4/keys/salts", cancel);
            var keySalts = saltsResp.GetProp("KeySalts");
            string? primarySaltB64 = null;
            for (int i = 0; ; i++)
            {
                if (!keySalts.TryGetAt(i, out var ks)) break;
                string ksSalt = ks.Str("KeySalt");
                if (!string.IsNullOrEmpty(ksSalt)) { primarySaltB64 = ksSalt; break; }
            }

            // ── Step 5: User private key ──────────────────────────────────────
            log("Fetching user keys...");
            var usersResp = await GetJsonAsync(http, "/core/v4/users", cancel);
            var userKeys = usersResp.GetProp("User").GetProp("Keys");
            string userKeyArmored = "";
            for (int i = 0; ; i++)
            {
                if (!userKeys.TryGetAt(i, out var uk)) break;
                if (uk.Int("Primary") == 1)
                {
                    userKeyArmored = uk.Str("PrivateKey");
                    break;
                }
            }

            if (string.IsNullOrEmpty(userKeyArmored))
            {
                log("ERROR: No primary user key found.");
                return false;
            }

            // ── Step 6: Derive key password ───────────────────────────────────
            log("Deriving key password...");
            byte[] keyPass;
            if (!string.IsNullOrEmpty(primarySaltB64))
            {
                byte[] keySaltBytes = FromB64(primarySaltB64);
                keyPass = Argon2idDeriveKey(Encoding.UTF8.GetBytes(password), keySaltBytes, 32);
            }
            else
            {
                keyPass = SHA256.HashData(Encoding.UTF8.GetBytes(password));
            }

            // ── Step 7: Decrypt user key ──────────────────────────────────────
            log("Decrypting user key...");
            RsaComponents? userRsa = DecryptPgpPrivateKey(userKeyArmored, keyPass);
            if (userRsa == null)
            {
                log("ERROR: Failed to decrypt user private key. Incorrect password?");
                return false;
            }

            // ── Step 8: Address key ───────────────────────────────────────────
            log("Fetching address key...");
            var addrResp = await GetJsonAsync(http, "/core/v4/addresses", cancel);
            var addresses = addrResp.GetProp("Addresses");

            string addressEmail   = "";
            string addrKeyArmored = "";
            string addrKeyToken   = "";
            for (int i = 0; ; i++)
            {
                if (!addresses.TryGetAt(i, out var addr)) break;
                var addrKeys = addr.GetProp("Keys");
                for (int k = 0; ; k++)
                {
                    if (!addrKeys.TryGetAt(k, out var ak)) break;
                    if (ak.Int("Primary") == 1)
                    {
                        addressEmail   = addr.Str("Email");
                        addrKeyArmored = ak.Str("PrivateKey");
                        addrKeyToken   = ak.Str("Token");
                        goto addrKeyFound;
                    }
                }
            }
            addrKeyFound:

            if (string.IsNullOrEmpty(addrKeyArmored))
            {
                log("ERROR: No primary address key found.");
                return false;
            }

            // ── Step 9: Decrypt address key passphrase ────────────────────────
            log("Decrypting address key...");
            byte[] addrKeyPass;
            if (!string.IsNullOrEmpty(addrKeyToken))
            {
                var decrypted = DecryptPgpMessage(addrKeyToken, userRsa);
                if (decrypted == null || decrypted.Length == 0)
                {
                    log("ERROR: Failed to decrypt address key token.");
                    return false;
                }
                addrKeyPass = decrypted;
            }
            else
            {
                addrKeyPass = keyPass;
            }

            RsaComponents? addrRsa = DecryptPgpPrivateKey(addrKeyArmored, addrKeyPass);
            if (addrRsa == null)
            {
                log("ERROR: Failed to decrypt address private key.");
                return false;
            }

            // ── Step 10: Drive volume / share ─────────────────────────────────
            log("Fetching drive metadata...");
            var volResp = await GetJsonAsync(http, "/drive/v2/volumes", cancel);
            var volumes = volResp.GetProp("Volumes");
            string volumeId = "";
            if (volumes.TryGetAt(0, out var vol))
                volumeId = vol.Str("VolumeID");

            if (string.IsNullOrEmpty(volumeId))
            {
                log("ERROR: No Drive volume found.");
                return false;
            }

            var sharesResp = await GetJsonAsync(http, $"/drive/v2/volumes/{volumeId}/shares", cancel);
            var shares = sharesResp.GetProp("Shares");
            string shareId    = "";
            string rootLinkId = "";
            for (int i = 0; ; i++)
            {
                if (!shares.TryGetAt(i, out var sh)) break;
                if (sh.Int("IsLocked") == 0 && sh.Int("Type") == 1)
                {
                    shareId    = sh.Str("ShareID");
                    rootLinkId = sh.Str("LinkID");
                    break;
                }
            }

            if (string.IsNullOrEmpty(shareId))
            {
                log("ERROR: No unlocked main drive share found.");
                return false;
            }

            // ── Step 11: Save token file ──────────────────────────────────────
            log("Saving token file...");
            var tokenObj = new Dictionary<string, object>
            {
                ["access_token"]  = accessToken,
                ["refresh_token"] = refreshToken,
                ["expires_at"]    = expiresAt,
                ["uid"]           = uid,
                ["volume_id"]     = volumeId,
                ["share_id"]      = shareId,
                ["root_link_id"]  = rootLinkId,
                ["address_email"] = addressEmail,
                ["address_key_n"]  = ToB64(addrRsa.N),
                ["address_key_e"]  = ToB64(addrRsa.E),
                ["address_key_d"]  = ToB64(addrRsa.D),
                ["address_key_p"]  = ToB64(addrRsa.P),
                ["address_key_q"]  = ToB64(addrRsa.Q),
                ["address_key_dp"] = ToB64(addrRsa.Dp),
                ["address_key_dq"] = ToB64(addrRsa.Dq),
                ["address_key_qi"] = ToB64(addrRsa.Qi),
            };

            string json = JsonSerializer.Serialize(tokenObj, new JsonSerializerOptions { WriteIndented = true });
            await Task.Run(() => TokenFile.WriteJson(tokenPath, json), cancel);

            log($"Token saved to: {tokenPath}");
            log("Authentication successful!");
            return true;
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            log($"ERROR: {ex.Message}");
            return false;
        }
    }

    // ── HTTP ───────────────────────────────────────────────────────────────────

    private static HttpClient BuildClient()
    {
        var client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        client.DefaultRequestHeaders.TryAddWithoutValidation("x-pm-appversion", AppVersion);
        return client;
    }

    private static async Task<JsonElement> PostJsonAsync(
        HttpClient http, string path, string body, CancellationToken cancel)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, ApiBase + path)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        };
        var resp = await http.SendAsync(req, cancel);
        var json = await resp.Content.ReadAsStringAsync(cancel);
        return JsonDocument.Parse(json).RootElement.Clone();
    }

    private static async Task<JsonElement> GetJsonAsync(
        HttpClient http, string path, CancellationToken cancel)
    {
        var resp = await http.GetAsync(ApiBase + path, cancel);
        var json = await resp.Content.ReadAsStringAsync(cancel);
        return JsonDocument.Parse(json).RootElement.Clone();
    }

    // ── SRP (go-srp compatible) ────────────────────────────────────────────────

    // expandHash: SHA-512(data||0) || SHA-512(data||1) || SHA-512(data||2) || SHA-512(data||3) = 256 bytes
    private static byte[] ExpandHash(byte[] data)
    {
        byte[] result = new byte[256];
        for (int i = 0; i < 4; i++)
        {
            byte[] tagged = new byte[data.Length + 1];
            data.CopyTo(tagged, 0);
            tagged[data.Length] = (byte)i;
            SHA512.HashData(tagged).CopyTo(result, i * 64);
        }
        return result;
    }

    // BCrypt base64 alphabet: ./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789
    private const string BcryptAlpha = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    private static string BcryptBase64Encode(byte[] data)
    {
        var sb = new System.Text.StringBuilder();
        for (int i = 0; i < data.Length; )
        {
            int b0 = data[i++];
            int b1 = i < data.Length ? data[i++] : 0;
            int b2 = i < data.Length ? data[i++] : 0;
            sb.Append(BcryptAlpha[b0 >> 2]);
            sb.Append(BcryptAlpha[((b0 & 3) << 4) | (b1 >> 4)]);
            sb.Append(BcryptAlpha[((b1 & 15) << 2) | (b2 >> 6)]);
            sb.Append(BcryptAlpha[b2 & 63]);
        }
        return sb.ToString();
    }

    private static byte[] BcryptBase64Decode(string s)
    {
        var result = new System.Collections.Generic.List<byte>();
        for (int i = 0; i + 1 < s.Length; )
        {
            int c0 = BcryptAlpha.IndexOf(s[i++]);
            int c1 = i < s.Length ? BcryptAlpha.IndexOf(s[i++]) : 0;
            int c2 = i < s.Length ? BcryptAlpha.IndexOf(s[i++]) : -1;
            int c3 = i < s.Length ? BcryptAlpha.IndexOf(s[i++]) : -1;
            result.Add((byte)((c0 << 2) | (c1 >> 4)));
            if (c2 >= 0) result.Add((byte)(((c1 & 15) << 4) | (c2 >> 2)));
            if (c3 >= 0) result.Add((byte)(((c2 & 3) << 6) | c3));
        }
        return result.ToArray();
    }

    // LE bytes ↔ BigInteger (go-srp uses little-endian throughout)
    private static BigInteger LEToInt(byte[] le)
    {
        byte[] be = (byte[])le.Clone();
        Array.Reverse(be);
        return new BigInteger(be, isUnsigned: true, isBigEndian: true);
    }

    private static byte[] IntToLE(BigInteger n, int byteLen)
    {
        byte[] be = n.ToByteArray(isUnsigned: true, isBigEndian: true);
        byte[] le = new byte[byteLen];
        int copy = Math.Min(be.Length, byteLen);
        for (int i = 0; i < copy; i++) le[i] = be[be.Length - 1 - i];
        return le;
    }

    // HashedPassword = expandHash(bcrypt("$2y$10$"+b64enc(salt+"proton")[:22]) || modulus_LE)
    private static byte[] ExpandPassword(string password, int version, byte[] salt, byte[] modulus)
    {
        if (version is 3 or 4)
        {
            byte[] saltProton = [.. salt, .. "proton"u8];
            string enc = BcryptBase64Encode(saltProton);
            string saltStr22 = enc.Length >= 22 ? enc[..22] : enc.PadRight(22, '.');

            // Decode to 16 binary bytes for BouncyCastle
            byte[] saltBin = BcryptBase64Decode(saltStr22);
            if (saltBin.Length > 16) Array.Resize(ref saltBin, 16);
            while (saltBin.Length < 16) saltBin = [.. saltBin, (byte)0];

            byte[] passBytes = Encoding.UTF8.GetBytes(password);
            int tlen = Math.Min(passBytes.Length, 72);
            char[] passChars = new char[tlen];
            for (int i = 0; i < tlen; i++) passChars[i] = (char)passBytes[i];

            string bcryptOut = Org.BouncyCastle.Crypto.Generators.OpenBsdBCrypt
                .Generate("2y", passChars, saltBin, 10);

            // BouncyCastle re-encodes salt16→22 chars which may differ by 1 char (trailing bits);
            // force the exact 22-char salt that go-srp uses so expandHash input matches.
            string corrected = "$2y$10$" + saltStr22 + bcryptOut[29..];
            byte[] cryptedBytes = Encoding.ASCII.GetBytes(corrected);

            return ExpandHash([.. cryptedBytes, .. modulus]);
        }
        return ExpandHash(SHA512.HashData(Encoding.UTF8.GetBytes(password)));
    }

    // SRP-6a, all values little-endian (matches go-srp)
    private static (byte[] clientEph, byte[] proof) SrpCompute(
        byte[] modulusLE, byte[] serverEphLE, byte[] hashedPassword)
    {
        int byteLen = modulusLE.Length;

        var N     = LEToInt(modulusLE);
        var g     = new BigInteger(2);
        var NMin1 = N - BigInteger.One;

        // k = toInt(expandHash(fromInt(bitLen, g) || fromInt(bitLen, N))) mod N
        var k = LEToInt(ExpandHash([.. IntToLE(g, byteLen), .. modulusLE])) % N;

        // Generate client secret a in (1, N-1)
        BigInteger a;
        do { a = LEToInt(RandomNumberGenerator.GetBytes(byteLen)); }
        while (a <= BigInteger.One || a >= N);

        var A = BigInteger.ModPow(g, a, N);
        byte[] A_LE = IntToLE(A, byteLen);

        // u = toNat(expandHash(A_LE || serverEphLE))
        var u = LEToInt(ExpandHash([.. A_LE, .. serverEphLE]));

        // x = toNat(hashedPassword)
        var x = LEToInt(hashedPassword);

        // B = toNat(serverEphLE)
        var B = LEToInt(serverEphLE);

        // S = (B - k*g^x mod N)^((u*x + a) mod N-1) mod N
        var gx    = BigInteger.ModPow(g, x, N);
        var base_ = ((B - k * gx % N) % N + N) % N;
        var exp_  = (u * x + a) % NMin1;
        var S     = BigInteger.ModPow(base_, exp_, N);
        byte[] S_LE = IntToLE(S, byteLen);

        // proof = expandHash(A_LE || serverEphLE || S_LE)
        byte[] proof = ExpandHash([.. A_LE, .. serverEphLE, .. S_LE]);

        return (A_LE, proof);
    }

    // ── Argon2id ───────────────────────────────────────────────────────────────

    private static byte[] Argon2idDeriveKey(byte[] password, byte[] salt, int keyLen)
    {
        using var argon2 = new Argon2id(password)
        {
            Salt                = salt,
            Iterations          = 4,
            MemorySize          = 65536,
            DegreeOfParallelism = 4,
        };
        return argon2.GetBytes(keyLen);
    }

    // ── PGP (BouncyCastle) ─────────────────────────────────────────────────────

    private sealed class RsaComponents
    {
        public byte[] N = [], E = [], D = [], P = [], Q = [], Dp = [], Dq = [], Qi = [];
    }

    private static RsaComponents? DecryptPgpPrivateKey(string armored, byte[] passphrase)
    {
        // BouncyCastle ExtractPrivateKey takes char[]; convert byte[] 1:1.
        char[] passChars = Array.ConvertAll(passphrase, b => (char)b);
        try
        {
            using var stream = new MemoryStream(Encoding.ASCII.GetBytes(armored));
            using var decoded = PgpUtilities.GetDecoderStream(stream);
            var factory = new PgpObjectFactory(decoded);

            PgpObject? obj;
            while ((obj = factory.NextPgpObject()) != null)
            {
                if (obj is PgpSecretKeyRing ring)
                {
                    var res = TryExtractFromRing(ring, passChars);
                    if (res != null) return res;
                }
            }
        }
        catch { }
        return null;
    }

    private static RsaComponents? TryExtractFromRing(PgpSecretKeyRing ring, char[] passChars)
    {
        foreach (PgpSecretKey sk in ring.GetSecretKeys())
        {
            try
            {
                var pk = sk.ExtractPrivateKey(passChars);
                if (pk?.Key is RsaPrivateCrtKeyParameters rsa)
                    return RsaToComponents(rsa);
            }
            catch { }
        }
        return null;
    }

    private static RsaComponents RsaToComponents(RsaPrivateCrtKeyParameters rsa) => new()
    {
        N  = rsa.Modulus.ToByteArrayUnsigned(),
        E  = rsa.PublicExponent.ToByteArrayUnsigned(),
        D  = rsa.Exponent.ToByteArrayUnsigned(),
        P  = rsa.P.ToByteArrayUnsigned(),
        Q  = rsa.Q.ToByteArrayUnsigned(),
        Dp = rsa.DP.ToByteArrayUnsigned(),
        Dq = rsa.DQ.ToByteArrayUnsigned(),
        Qi = rsa.QInv.ToByteArrayUnsigned(),
    };

    private static byte[]? DecryptPgpMessage(string armored, RsaComponents rsa)
    {
        try
        {
            var privParams = new RsaPrivateCrtKeyParameters(
                new Org.BouncyCastle.Math.BigInteger(1, rsa.N),
                new Org.BouncyCastle.Math.BigInteger(1, rsa.E),
                new Org.BouncyCastle.Math.BigInteger(1, rsa.D),
                new Org.BouncyCastle.Math.BigInteger(1, rsa.P),
                new Org.BouncyCastle.Math.BigInteger(1, rsa.Q),
                new Org.BouncyCastle.Math.BigInteger(1, rsa.Dp),
                new Org.BouncyCastle.Math.BigInteger(1, rsa.Dq),
                new Org.BouncyCastle.Math.BigInteger(1, rsa.Qi));

            using var stream  = new MemoryStream(Encoding.ASCII.GetBytes(armored));
            using var decoded = PgpUtilities.GetDecoderStream(stream);
            var factory = new PgpObjectFactory(decoded);

            PgpEncryptedDataList? encList = null;
            PgpObject? obj;
            while ((obj = factory.NextPgpObject()) != null)
            {
                if (obj is PgpEncryptedDataList edl) { encList = edl; break; }
            }
            if (encList == null) return null;

            // Build PgpPrivateKey — GetDataStream requires PgpPrivateKey in BC 2.x.
            // We reconstruct it from raw RSA components with a minimal PublicKeyPacket.
            var rsaBcpgKey = new RsaPublicBcpgKey(
                new Org.BouncyCastle.Math.BigInteger(1, rsa.N),
                new Org.BouncyCastle.Math.BigInteger(1, rsa.E));
            var pubKeyPacket = new PublicKeyPacket(
                PublicKeyAlgorithmTag.RsaEncrypt, DateTime.UtcNow, rsaBcpgKey);

            foreach (PgpPublicKeyEncryptedData pked in encList.GetEncryptedDataObjects())
            {
                try
                {
                    var pgpPrivKey = new PgpPrivateKey(pked.KeyId, pubKeyPacket, privParams);
                    using var plain = pked.GetDataStream(pgpPrivKey);
                    var inner = new PgpObjectFactory(plain);
                    PgpObject? innerObj;
                    while ((innerObj = inner.NextPgpObject()) != null)
                    {
                        if (innerObj is PgpCompressedData cd)
                        {
                            inner = new PgpObjectFactory(cd.GetDataStream());
                            continue;
                        }
                        if (innerObj is PgpLiteralData lit)
                        {
                            using var ms = new MemoryStream();
                            lit.GetInputStream().CopyTo(ms);
                            return ms.ToArray();
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
        return null;
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    // The Modulus field in /auth/v4/info is a PGP clearsign message; body is standard base64.
    private static byte[] ParseSrpModulus(string pgpSigned)
    {
        var lines = pgpSigned.Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.None);
        bool inBody = false;
        var b64 = new System.Text.StringBuilder();
        foreach (var line in lines)
        {
            if (!inBody) { if (line.Trim().Length == 0) inBody = true; continue; }
            if (line.StartsWith("-----") || line.StartsWith("=")) break;
            b64.Append(line.Trim());
        }
        return Convert.FromBase64String(b64.ToString());
    }

    private static string ToB64(byte[] b)  => Convert.ToBase64String(b);
    private static byte[] FromB64(string s) => Convert.FromBase64String(s);

    private static string JsonEscape(string s)
    {
        var sb = new StringBuilder("\"");
        foreach (char c in s)
            switch (c)
            {
                case '"':  sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n");  break;
                case '\r': sb.Append("\\r");  break;
                default:   sb.Append(c);      break;
            }
        sb.Append('"');
        return sb.ToString();
    }

    private static int    GetInt (JsonElement j, string k) => j.TryGetProperty(k, out var v) ? (v.ValueKind == JsonValueKind.Number ? v.GetInt32() : 0) : 0;
    private static long   GetLong(JsonElement j, string k) => j.TryGetProperty(k, out var v) ? (v.ValueKind == JsonValueKind.Number ? v.GetInt64() : 0) : 0;
    private static string GetStr (JsonElement j, string k) => j.TryGetProperty(k, out var v) ? v.GetString() ?? "" : "";
}

// Extension methods for concise JSON navigation
file static class JExt
{
    public static JsonElement GetProp(this JsonElement el, string key)
        => el.TryGetProperty(key, out var v) ? v : JsonDocument.Parse("{}").RootElement;

    public static bool TryGetAt(this JsonElement arr, int i, out JsonElement el)
    {
        if (arr.ValueKind == JsonValueKind.Array && i < arr.GetArrayLength())
        { el = arr[i]; return true; }
        el = default; return false;
    }

    public static string Str(this JsonElement el, string key)
        => el.TryGetProperty(key, out var v) ? v.GetString() ?? "" : "";

    public static int Int(this JsonElement el, string key)
        => el.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : 0;
}
