using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Net.Http;
using System.Net.Http.Headers;
using CloudRedirect.Windows;
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
    private const string ApiBase = "https://mail.proton.me/api";
    private const string AppVersion = "windows-drive@2.1.0";
    private const string UserAgent  = "ProtonDrive/2.1.0 (Windows)";

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
                $"{{\"Username\":{JsonEscape(email)}}}",
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
            log($"Computing SRP proof (version={srpVersion}, modLen={ParseSrpModulus(modHex).Length}, saltLen={FromB64(srpSalt).Length}, ephLen={FromB64(serverEph).Length})...");
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
                              $"\"SRPSession\":{JsonEscape(sessionId)}}}";

            var auth = await PostJsonAsync(http, "/auth/v4", authBody, cancel);
            int authCode = GetInt(auth, "Code");
            if (authCode != 1000)
            {
                string authErr = auth.TryGetProperty("Error", out var ep) ? ep.GetString() ?? "" : "";
                log($"ERROR: Authentication failed — Code {authCode}: {authErr}");
                if (authCode == 8002) log("Hint: Incorrect password.");
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

            // ── Step 3b: Two-factor authentication ────────────────────────────
            bool twoFaRequired = auth.TryGetProperty("TwoFactor", out var tf)
                && tf.TryGetProperty("Enabled", out var tfEnabled)
                && (tfEnabled.GetInt32() & 1) != 0;

            if (twoFaRequired)
            {
                log("Two-factor authentication required...");
                string twoFaCode = "";
                await System.Windows.Application.Current.Dispatcher.InvokeAsync(() =>
                {
                    var twoFaWin = new ProtonTwoFaWindow
                    {
                        Owner = System.Windows.Application.Current.MainWindow
                    };
                    if (twoFaWin.ShowDialog() == true)
                        twoFaCode = twoFaWin.TotpCode;
                });

                if (string.IsNullOrEmpty(twoFaCode))
                {
                    log("Two-factor authentication cancelled.");
                    return false;
                }

                log("Submitting two-factor code...");
                var twoFaResp = await PostJsonAsync(http, "/auth/v4/2fa",
                    $"{{\"TwoFactorCode\":{JsonEscape(twoFaCode)}}}", cancel);
                int twoFaResult = GetInt(twoFaResp, "Code");
                if (twoFaResult != 1000)
                {
                    string twoFaErr = twoFaResp.TryGetProperty("Error", out var twoFaEp)
                        ? twoFaEp.GetString() ?? "" : "";
                    log($"ERROR: Two-factor authentication failed — Code {twoFaResult}: {twoFaErr}");
                    return false;
                }
            }

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
                keyPass = MailboxPassword(password, keySaltBytes);
            }
            else
            {
                keyPass = SHA256.HashData(Encoding.UTF8.GetBytes(password));
            }

            // ── Step 7: Decrypt user key ──────────────────────────────────────
            log("Decrypting user key...");
            PgpKeyResult? userKey = DecryptPgpPrivateKey(userKeyArmored, keyPass);
            if (userKey == null)
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
                var decrypted = DecryptPgpMessage(addrKeyToken, userKey);
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

            PgpKeyResult? addrKey = DecryptPgpPrivateKey(addrKeyArmored, addrKeyPass);
            if (addrKey == null)
            {
                log("ERROR: Failed to decrypt address private key.");
                return false;
            }

            // ── Step 10: Drive share ──────────────────────────────────────────
            log("Fetching drive metadata...");
            var sharesResp = await GetJsonAsync(http, "/drive/shares", cancel);
            var shares = sharesResp.GetProp("Shares");
            string volumeId   = "";
            string shareId    = "";
            string rootLinkId = "";
            for (int i = 0; ; i++)
            {
                if (!shares.TryGetAt(i, out var sh)) break;
                bool locked = sh.TryGetProperty("Locked", out var lv) && lv.ValueKind == JsonValueKind.True;
                if (!locked && sh.Int("Type") == 1)
                {
                    volumeId   = sh.Str("VolumeID");
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
                ["address_key_type"] = addrKey.IsEcc ? "ecc" : "rsa",
            };

            if (addrKey.IsEcc)
            {
                if (addrKey.X25519Priv  != null) tokenObj["address_x25519_priv"]  = ToB64(addrKey.X25519Priv);
                if (addrKey.X25519Pub   != null) tokenObj["address_x25519_pub"]   = ToB64(addrKey.X25519Pub);
                if (addrKey.Ed25519Priv != null) tokenObj["address_ed25519_priv"] = ToB64(addrKey.Ed25519Priv);
                if (addrKey.Ed25519Pub  != null) tokenObj["address_ed25519_pub"]  = ToB64(addrKey.Ed25519Pub);
            }
            else
            {
                tokenObj["address_key_n"]  = ToB64(addrKey.N!);
                tokenObj["address_key_e"]  = ToB64(addrKey.E!);
                tokenObj["address_key_d"]  = ToB64(addrKey.D!);
                tokenObj["address_key_p"]  = ToB64(addrKey.P!);
                tokenObj["address_key_q"]  = ToB64(addrKey.Q!);
                tokenObj["address_key_dp"] = ToB64(addrKey.Dp!);
                tokenObj["address_key_dq"] = ToB64(addrKey.Dq!);
                tokenObj["address_key_qi"] = ToB64(addrKey.Qi!);
            }

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
        client.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", UserAgent);
        client.DefaultRequestHeaders.TryAddWithoutValidation("Accept", "application/vnd.protonmail.api+json");
        client.DefaultRequestHeaders.TryAddWithoutValidation("Accept-Language", "en-US,en");
        client.DefaultRequestHeaders.TryAddWithoutValidation("x-pm-locale", "en_US");
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

    // ── Key passphrase (go-srp MailboxPassword) ────────────────────────────────
    // bcrypt(password, $2y$10$<bcryptBase64(keySalt)[:22]>, cost=10) → take chars [29..] as bytes

    private static byte[] MailboxPassword(string password, byte[] keySalt)
    {
        string enc = BcryptBase64Encode(keySalt);
        string saltStr22 = enc.Length >= 22 ? enc[..22] : enc.PadRight(22, '.');

        byte[] saltBin = BcryptBase64Decode(saltStr22);
        if (saltBin.Length > 16) Array.Resize(ref saltBin, 16);
        while (saltBin.Length < 16) saltBin = [.. saltBin, (byte)0];

        byte[] passBytes = Encoding.UTF8.GetBytes(password);
        int tlen = Math.Min(passBytes.Length, 72);
        char[] passChars = new char[tlen];
        for (int i = 0; i < tlen; i++) passChars[i] = (char)passBytes[i];

        string bcryptOut = Org.BouncyCastle.Crypto.Generators.OpenBsdBCrypt
            .Generate("2y", passChars, saltBin, 10);

        // bcryptOut is "$2y$10$<22-salt><31-hash>" (60 chars); reconstruct with exact salt
        string full = "$2y$10$" + saltStr22 + bcryptOut[29..];
        return Encoding.ASCII.GetBytes(full[29..]);
    }

    // ── PGP (BouncyCastle) ─────────────────────────────────────────────────────

    private sealed class PgpKeyResult
    {
        // Session-only: held for PGP decryption within the auth flow
        public PgpPrivateKey? EncryptionSubkey; // X25519 (ECDH) or RSA

        // ECC key material for token file
        public bool IsEcc;
        public byte[]? X25519Priv, X25519Pub, Ed25519Priv, Ed25519Pub;

        // RSA key material for token file (legacy/fallback)
        public byte[]? N, E, D, P, Q, Dp, Dq, Qi;
    }

    private static PgpKeyResult? DecryptPgpPrivateKey(string armored, byte[] passphrase)
    {
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

    private static PgpKeyResult? TryExtractFromRing(PgpSecretKeyRing ring, char[] passChars)
    {
        var result = new PgpKeyResult();

        foreach (PgpSecretKey sk in ring.GetSecretKeys())
        {
            try
            {
                var pk = sk.ExtractPrivateKey(passChars);

                if (pk == null) continue;

                if (pk.Key is RsaPrivateCrtKeyParameters rsa)
                {
                    result.N  = rsa.Modulus.ToByteArrayUnsigned();
                    result.E  = rsa.PublicExponent.ToByteArrayUnsigned();
                    result.D  = rsa.Exponent.ToByteArrayUnsigned();
                    result.P  = rsa.P.ToByteArrayUnsigned();
                    result.Q  = rsa.Q.ToByteArrayUnsigned();
                    result.Dp = rsa.DP.ToByteArrayUnsigned();
                    result.Dq = rsa.DQ.ToByteArrayUnsigned();
                    result.Qi = rsa.QInv.ToByteArrayUnsigned();
                    result.EncryptionSubkey ??= pk;
                }
                else if (pk.Key is X25519PrivateKeyParameters x25519)
                {
                    result.IsEcc = true;
                    result.X25519Priv = x25519.GetEncoded();
                    result.X25519Pub  = ((X25519PublicKeyParameters)x25519.GeneratePublicKey()).GetEncoded();
                    result.EncryptionSubkey = pk; // X25519 is the encryption subkey
                }
                else if (pk.Key is Ed25519PrivateKeyParameters ed25519)
                {
                    result.IsEcc = true;
                    result.Ed25519Priv = ed25519.GetEncoded();
                    result.Ed25519Pub  = ((Ed25519PublicKeyParameters)ed25519.GeneratePublicKey()).GetEncoded();
                }
            }
            catch { }
        }

        return (result.EncryptionSubkey != null) ? result : null;
    }

    private static byte[]? DecryptPgpMessage(string armored, PgpKeyResult key)
    {
        try
        {
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

            foreach (PgpPublicKeyEncryptedData pked in encList.GetEncryptedDataObjects())
            {
                try
                {
                    PgpPrivateKey decryptKey;
                    if (key.IsEcc && key.EncryptionSubkey != null)
                    {
                        decryptKey = key.EncryptionSubkey;
                    }
                    else if (!key.IsEcc && key.N != null)
                    {
                        var rsaBcpgKey2 = new RsaPublicBcpgKey(
                            new Org.BouncyCastle.Math.BigInteger(1, key.N),
                            new Org.BouncyCastle.Math.BigInteger(1, key.E!));
                        var pubKeyPacket2 = new PublicKeyPacket(
                            PublicKeyAlgorithmTag.RsaEncrypt, DateTime.UtcNow, rsaBcpgKey2);
                        var privParams2 = new RsaPrivateCrtKeyParameters(
                            new Org.BouncyCastle.Math.BigInteger(1, key.N),
                            new Org.BouncyCastle.Math.BigInteger(1, key.E!),
                            new Org.BouncyCastle.Math.BigInteger(1, key.D!),
                            new Org.BouncyCastle.Math.BigInteger(1, key.P!),
                            new Org.BouncyCastle.Math.BigInteger(1, key.Q!),
                            new Org.BouncyCastle.Math.BigInteger(1, key.Dp!),
                            new Org.BouncyCastle.Math.BigInteger(1, key.Dq!),
                            new Org.BouncyCastle.Math.BigInteger(1, key.Qi!));
                        decryptKey = new PgpPrivateKey(pked.KeyId, pubKeyPacket2, privParams2);
                    }
                    else continue;

                    using var plain = pked.GetDataStream(decryptKey);
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
