using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Security.Cryptography;
using CloudRedirect.Services;
using Microsoft.Win32;

namespace CloudRedirect.Services.Patching
{
    internal class Patcher
    {
        class CloudRedirectResolveResult
        {
            public PatchEntry[] Patches;
            public byte[] DynamicCodeCave;
            public int CodeCaveFileOffset;
        }

        static readonly string[] HijackCandidates = { "xinput1_4.dll", "dwmapi.dll" };

        static readonly byte[] AesKey = SteamToolsCrypto.AesKey;

        const int CloudRedirectCaveMinSize = 144; // CloudRedirectCaveContent.Length

        static readonly byte[] CloudRedirectCaveContent =
        {
            // [0x00] ENTRY: save volatile regs + rbx on stack (no RIP-relative writes)
            0x51,                                             // push rcx
            0x52,                                             // push rdx
            0x41, 0x50,                                       // push r8
            0x53,                                             // push rbx
            0x48, 0x83, 0xEC, 0x28,                           // sub rsp, 0x28
            // LoadLibrary("cloud_redirect.dll")
            0x48, 0x8D, 0x0D, 0x5E, 0x00, 0x00, 0x00,       // lea rcx, [rip+0x5E]  -> "cloud_redirect.dll"
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,              // call [rip+XX]        -> LoadLibraryA IAT
            // check result
            0x48, 0x85, 0xC0,                                 // test rax, rax
            0x74, 0x34,                                       // jz fallthrough
            // GetProcAddress(rax, "CloudOnSendPkt")
            0x48, 0x8D, 0x15, 0x5F, 0x00, 0x00, 0x00,       // lea rdx, [rip+0x5F]  -> "CloudOnSendPkt"
            0x48, 0x8B, 0xC8,                                 // mov rcx, rax
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,              // call [rip+XX]        -> GetProcAddress IAT
            // check result
            0x48, 0x85, 0xC0,                                 // test rax, rax
            0x74, 0x1F,                                       // jz fallthrough
            // call CloudOnSendPkt(thisptr, data, size, recvPktFn)
            0x48, 0x8B, 0xD8,                                 // mov rbx, rax
            0x48, 0x8B, 0x4C, 0x24, 0x40,                    // mov rcx, [rsp+0x40]
            0x48, 0x8B, 0x54, 0x24, 0x38,                    // mov rdx, [rsp+0x38]
            0x4C, 0x8B, 0x44, 0x24, 0x30,                    // mov r8,  [rsp+0x30]
            0x4C, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,       // lea r9,  [rip+XX]    -> &qword_1801CAB48
            0xFF, 0xD3,                                       // call rbx
            // check return value
            0x85, 0xC0,                                       // test eax, eax
            0x75, 0x13,                                       // jnz handled
            // [0x4F] FALLTHROUGH: restore and execute original prologue
            0x48, 0x83, 0xC4, 0x28,                           // add rsp, 0x28
            0x5B,                                             // pop rbx
            0x41, 0x58,                                       // pop r8
            0x5A,                                             // pop rdx
            0x59,                                             // pop rcx
            0x48, 0x89, 0x5C, 0x24, 0x20,                    // mov [rsp+20h], rbx  (original 5 bytes)
            0xE9, 0x00, 0x00, 0x00, 0x00,                    // jmp SendPkt+5
            // [0x62] HANDLED: clean up and return 1
            0x48, 0x83, 0xC4, 0x28,                           // add rsp, 0x28
            0x5B,                                             // pop rbx
            0x41, 0x58,                                       // pop r8
            0x5A,                                             // pop rdx
            0x59,                                             // pop rcx
            0xB0, 0x01,                                       // mov al, 1
            0xC3,                                             // ret
            // [0x6E] string data
            0x63, 0x6C, 0x6F, 0x75, 0x64, 0x5F, 0x72, 0x65, // "cloud_re"
            0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x2E, 0x64, // "direct.d"
            0x6C, 0x6C, 0x00,                                 // "ll\0"
            // [0x81] "CloudOnSendPkt\0"
            0x43, 0x6C, 0x6F, 0x75, 0x64, 0x4F, 0x6E, 0x53,
            0x65, 0x6E, 0x64, 0x50, 0x6B, 0x74, 0x00,
        };

        string _steamPath;
        bool _verbose;
        Action<string> _log;

        byte[] _cachedPayload;
        long _cachedPayloadSize;
        DateTime _cachedPayloadTime;

        public Patcher(string steamPath, Action<string> log = null)
        {
            _steamPath = steamPath;
            _log = log;
        }

        static byte[] ReadFileShared(string path)
        {
            // FileShare.Read prevents concurrent writes from modifying the file
            // while we're reading, avoiding TOCTOU races with SteamTools deployment
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            var buf = new byte[fs.Length];
            fs.ReadExactly(buf);
            return buf;
        }

        byte[] GetDecryptedPayload(string cachePath)
        {
            var info = new FileInfo(cachePath);
            if (!info.Exists) return null;

            long size = info.Length;
            var lastWrite = info.LastWriteTimeUtc;
            if (_cachedPayload != null && _cachedPayloadSize == size && _cachedPayloadTime == lastWrite)
                return _cachedPayload;

            byte[] raw;
            try
            {
                using var fs = new FileStream(cachePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                raw = new byte[fs.Length];
                fs.ReadExactly(raw);
            }
            catch (IOException) { return null; }

            if (raw.Length < 32) return null;

            try
            {
                var iv = raw.AsSpan(0, 16).ToArray();
                var ct = raw.AsSpan(16).ToArray();
                var dec = PayloadCrypto.AesCbcDecrypt(ct, AesKey, iv);
                if (dec.Length < 4) return null;
                using var zIn = new ZLibStream(
                    new MemoryStream(dec, 4, dec.Length - 4),
                    CompressionMode.Decompress);
                using var ms = new MemoryStream();
                zIn.CopyTo(ms);
                _cachedPayload = ms.ToArray();
                _cachedPayloadSize = size;
                _cachedPayloadTime = lastWrite;
                return _cachedPayload;
            }
            catch { return null; }
        }

        (byte[] payload, byte[] iv, string error) ReadAndDecryptPayload(string cachePath)
        {
            byte[] raw;
            try { raw = ReadFileShared(cachePath); }
            catch (IOException) { return (null, null, "Payload cache is in use - close Steam first"); }

            if (raw.Length < 32)
                return (null, null, "Cache file too small");

            var iv = raw.AsSpan(0, 16).ToArray();
            var ct = raw.AsSpan(16).ToArray();

            Log("  Decrypting..");
            byte[] dec;
            try { dec = PayloadCrypto.AesCbcDecrypt(ct, AesKey, iv); }
            catch (Exception ex) { return (null, null, $"Decryption failed: {ex.Message}"); }

            if (dec.Length < 4)
                return (null, null, "Decrypted payload too small");

            byte[] payload;
            try
            {
                using var zIn = new ZLibStream(
                    new MemoryStream(dec, 4, dec.Length - 4),
                    CompressionMode.Decompress);
                using var ms = new MemoryStream();
                zIn.CopyTo(ms);
                payload = ms.ToArray();
            }
            catch (Exception ex) { return (null, null, $"Decompression failed: {ex.Message}"); }

            Log($"  Payload: {payload.Length} bytes");
            return (payload, iv, null);
        }

        string FindCoreDll()
        {
            foreach (var name in HijackCandidates)
            {
                var path = Path.Combine(_steamPath, name);
                if (!File.Exists(path)) continue;

                try
                {
                    using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    var buf = new byte[fs.Length];
                    fs.ReadExactly(buf);

                    if (Signatures.ScanForBytes(buf, 0, buf.Length, AesKey) >= 0)
                        return name;
                }
                catch (IOException) { }
            }
            return null;
        }

        public bool HasCoreDll() => FindCoreDll() != null;

        public bool HasPayloadCache() => Fingerprint.FindCachePath(_steamPath, verbose: false, log: _log) != null;

        const string XinputUrl = "https://update.aaasn.com/update";
        const string DwmapiUrl = "https://update.aaasn.com/dwmapi";
        const string XinputFallbackUrl = "https://files.catbox.moe/heom44.dll";
        const string DwmapiFallbackUrl = "https://files.catbox.moe/32p6f9.dll";
        const string XinputHash = "ddb1f0909c7092f06890674f90b5d4f1198724b05b4bf1e656b4063897340243";
        const string DwmapiHash = "1ce49ed63af004ad37a4d2921a5659a17001c4c0026d6245fcc0d543e9c265d0";

        static string ComputeSha256(byte[] data)
        {
            var hash = SHA256.HashData(data);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }

        public PatchResult RepairCoreDlls()
        {
            _verbose = true;
            var result = new PatchResult();

            try
            {
                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
                http.DefaultRequestHeaders.UserAgent.ParseAdd("Stella/1.0");

                var targets = new[]
                {
                    (name: "xinput1_4.dll", url: XinputUrl, fallback: XinputFallbackUrl, hash: XinputHash),
                    (name: "dwmapi.dll",    url: DwmapiUrl, fallback: DwmapiFallbackUrl, hash: DwmapiHash),
                };

                foreach (var (name, url, fallback, hash) in targets)
                {
                    var destPath = Path.Combine(_steamPath, name);

                    if (File.Exists(destPath))
                    {
                        try
                        {
                            var existing = ReadFileShared(destPath);
                            if (ComputeSha256(existing) == hash)
                            {
                                Log($"  {name}: already present, hash OK");
                                continue;
                            }
                            Log($"  {name}: present but hash mismatch, re-downloading..");
                        }
                        catch (IOException)
                        {
                            Log($"  {name}: could not read existing file, re-downloading..");
                        }
                    }

                    byte[] data = null;
                    bool fromFallback = false;

                    Log($"Downloading {name}..");
                    try
                    {
                        data = http.GetByteArrayAsync(url).ConfigureAwait(false).GetAwaiter().GetResult();
                    }
                    catch (Exception ex)
                    {
                        Log($"  Primary failed: {ex.Message}");
                    }

                    if (data != null && ComputeSha256(data) != hash)
                    {
                        Log($"  Hash mismatch from primary, trying fallback..");
                        data = null;
                    }

                    if (data == null)
                    {
                        Log($"  Trying fallback source..");
                        try
                        {
                            data = http.GetByteArrayAsync(fallback).ConfigureAwait(false).GetAwaiter().GetResult();
                            fromFallback = true;
                        }
                        catch (Exception ex)
                        {
                            return result.Fail($"Could not download {name}: {ex.Message}");
                        }

                        string got = ComputeSha256(data);
                        if (got != hash)
                            return result.Fail($"{name} hash mismatch from fallback ({got[..12]}.. != {hash[..12]}..)");
                    }

                    try
                    {
                        FileUtils.AtomicWriteAllBytes(destPath, data);
                        Log($"  {name}: {data.Length} bytes" + (fromFallback ? " (fallback)" : ""));
                    }
                    catch (IOException ex)
                    {
                        return result.Fail($"Could not write {name}: {ex.Message}");
                    }
                }

                result.DllPatched = true;
                result.Succeeded = true;
                Log("DLL repair complete.");
            }
            catch (Exception ex)
            {
                result.Fail($"Unexpected error: {ex.Message}");
            }

            return result;
        }

        public PatchState GetPatchState()
        {
            _verbose = false;
            var hijackDll = FindCoreDll();
            if (hijackDll == null)
                return PatchState.NotInstalled;

            var dllPath = Path.Combine(_steamPath, hijackDll);

            byte[] dll;
            try
            {
                using var fs = new FileStream(dllPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                dll = new byte[fs.Length];
                fs.ReadExactly(dll);
            }
            catch (IOException)
            {
                return PatchState.UnknownVersion;
            }

            var resolvedCore = ResolveCorePatchOffsets(dll);
            if (resolvedCore == null)
                return PatchState.UnknownVersion;

            var (_, applied, skipped, errors) = CheckPatches(dll, resolvedCore);

            if (errors.Count > 0)
                return PatchState.OutOfDate;
            if (applied == 0 && skipped == resolvedCore.Length)
                return PatchState.Patched;
            if (skipped == 0 && applied == resolvedCore.Length)
                return PatchState.Unpatched;

            return PatchState.PartiallyPatched;
        }

        public PatchState GetOfflinePatchState()
        {
            _verbose = false;

            var cachePath = Fingerprint.FindCachePath(_steamPath, verbose: false, log: _log);
            if (cachePath == null)
                return PatchState.NotInstalled;

            var payload = GetDecryptedPayload(cachePath);
            if (payload == null)
                return PatchState.UnknownVersion;

            var resolved = ResolveSetupPatchOffsets(payload);
            if (resolved == null)
                return PatchState.UnknownVersion;

            var (_, applied, skipped, errors) = CheckPatches(payload, resolved);

            if (errors.Count > 0)
                return PatchState.OutOfDate;
            if (applied == 0 && skipped == resolved.Length)
                return PatchState.Patched;
            if (skipped == 0 && applied == resolved.Length)
                return PatchState.Unpatched;

            return PatchState.PartiallyPatched;
        }

        public PatchResult ApplyOfflineSetup()
        {
            _verbose = true;
            var result = new PatchResult();

            var version = SteamDetector.GetSteamVersion(_steamPath);
            if (version == null)
            {
                Log("  WARNING: Could not read Steam version from manifest");
                return result.Fail("Steam version could not be determined. Cannot safely patch.");
            }
            if (version.Value != SteamDetector.ExpectedSteamVersion)
            {
                Log($"  Steam version: {version.Value} (UNSUPPORTED)");
                Log($"  Expected version: {SteamDetector.ExpectedSteamVersion}");
                return result.Fail(
                    $"Steam version mismatch: installed {version.Value}, " +
                    $"expected {SteamDetector.ExpectedSteamVersion}. " +
                    "Patching an unsupported version risks corrupting steamclient64.dll. " +
                    "Update CloudRedirect or downgrade Steam.");
            }
            Log($"  Steam version: {version.Value} (OK)");

            try
            {
                var hijackDll = FindCoreDll();
                if (hijackDll == null)
                    return result.Fail("SteamTools Core DLL not found. Is SteamTools installed?");

                var dllPath = Path.Combine(_steamPath, hijackDll);
                byte[] dllData;
                try { dllData = ReadFileShared(dllPath); }
                catch (IOException) { return result.Fail($"{hijackDll} is in use - close Steam first"); }

                Log($"Patching {hijackDll}..");
                var resolvedCore = ResolveCorePatchOffsets(dllData);
                if (resolvedCore == null)
                    return result.Fail($"Could not identify patch locations in {hijackDll} - unsupported version?");

                var (patchedDll, dllApplied, dllSkipped, dllErrors) = ApplyPatches(dllData, resolvedCore);
                if (dllErrors.Count > 0)
                {
                    foreach (var err in dllErrors) Log(err);
                    return result.Fail("Byte mismatch in " + hijackDll + " - wrong version?");
                }

                var cachePath = Fingerprint.FindCachePath(_steamPath, log: _log);
                if (cachePath == null)
                {
                    Log("Payload cache not found. Deploying embedded payload..");
                    cachePath = DeployEmbeddedPayload();
                    if (cachePath == null)
                        return result.Fail("Could not deploy payload cache.");
                }

                Log("Patching payload (offline setup)..");

                var (payload, iv, plErr) = ReadAndDecryptPayload(cachePath);
                if (payload == null)
                    return result.Fail(plErr);

                var resolvedSetup = ResolveSetupPatchOffsets(payload);
                if (resolvedSetup == null)
                    return result.Fail("Could not identify activation patch locations in payload - unsupported version?");

                var (patchedPayload, plApplied, plSkipped, plErrors) = ApplyPatches(payload, resolvedSetup);
                if (plErrors.Count > 0)
                {
                    foreach (var err in plErrors) Log(err);
                    return result.Fail("Byte mismatch in payload - wrong version?");
                }

                // all patches verified - now write both files
                // Write payload first (less dangerous if interrupted: patched payload
                // without patched DLL just means cloud features don't work yet, while
                // patched DLL with original payload would bypass SteamTools activation)
                Backup(cachePath);
                if (plApplied > 0)
                {
                    ReEncryptAndWrite(cachePath, patchedPayload, iv);
                    Log($"  {plApplied} patch(es) applied to payload" + (plSkipped > 0 ? $", {plSkipped} already done" : ""));
                }
                else
                {
                    Log("  Payload: already patched");
                }
                result.CachePatched = true;

                Backup(dllPath);
                if (dllApplied > 0)
                {
                    FileUtils.AtomicWriteAllBytes(dllPath, patchedDll);
                    Log($"  {dllApplied} patch(es) applied to {hijackDll}" + (dllSkipped > 0 ? $", {dllSkipped} already done" : ""));
                }
                else
                {
                    Log($"  {hijackDll}: already patched");
                }
                result.DllPatched = true;

                result.Succeeded = true;
                Log("Done.");
            }
            catch (Exception ex)
            {
                result.Fail($"Unexpected error: {ex.Message}");
                Log($"Error: {ex.Message}");
            }

            return result;
        }

        public PatchResult RevertOfflineSetup()
        {
            _verbose = true;
            var result = new PatchResult();

            var version = SteamDetector.GetSteamVersion(_steamPath);
            if (version == null)
            {
                Log("  WARNING: Could not read Steam version from manifest");
                return result.Fail("Steam version could not be determined. Cannot safely revert.");
            }
            if (version.Value != SteamDetector.ExpectedSteamVersion)
            {
                Log($"  Steam version: {version.Value} (UNSUPPORTED)");
                Log($"  Expected version: {SteamDetector.ExpectedSteamVersion}");
                return result.Fail(
                    $"Steam version mismatch: installed {version.Value}, " +
                    $"expected {SteamDetector.ExpectedSteamVersion}. " +
                    "Reverting on an unsupported version risks corrupting steamclient64.dll. " +
                    "Update CloudRedirect or downgrade Steam.");
            }
            Log($"  Steam version: {version.Value} (OK)");

            try
            {
                var hijackDll = FindCoreDll();
                if (hijackDll == null)
                    return result.Fail("SteamTools Core DLL not found.");

                var dllPath = Path.Combine(_steamPath, hijackDll);
                byte[] dllData;
                try { dllData = ReadFileShared(dllPath); }
                catch (IOException) { return result.Fail($"{hijackDll} is in use - close Steam first"); }

                var resolvedCore = ResolveCorePatchOffsets(dllData);
                if (resolvedCore == null)
                    return result.Fail($"Could not identify patch locations in {hijackDll}");

                var (revertedDll, dllReverted, dllSkipped, dllErrors) = UnapplyPatches(dllData, resolvedCore);
                if (dllErrors.Count > 0)
                {
                    foreach (var err in dllErrors) Log(err);
                    return result.Fail("Byte mismatch in " + hijackDll);
                }

                var cachePath = Fingerprint.FindCachePath(_steamPath, verbose: false, log: _log);
                if (cachePath == null)
                    return result.Fail("Payload cache not found.");

                var (payload, iv, plErr) = ReadAndDecryptPayload(cachePath);
                if (payload == null)
                    return result.Fail(plErr);

                var resolvedSetup = ResolveSetupPatchOffsets(payload);
                if (resolvedSetup == null)
                    return result.Fail("Could not identify patch locations in payload");

                var (revertedPayload, plReverted, plSkipped, plErrors) = UnapplyPatches(payload, resolvedSetup);
                if (plErrors.Count > 0)
                {
                    foreach (var err in plErrors) Log(err);
                    return result.Fail("Byte mismatch in payload");
                }

                if (plReverted > 0)
                {
                    Backup(cachePath);
                    ReEncryptAndWrite(cachePath, revertedPayload, iv);
                    Log($"  {plReverted} patch(es) reverted in payload" + (plSkipped > 0 ? $", {plSkipped} already original" : ""));
                }
                else
                {
                    Log("  Payload: already original");
                }

                if (dllReverted > 0)
                {
                    Backup(dllPath);
                    FileUtils.AtomicWriteAllBytes(dllPath, revertedDll);
                    Log($"  {dllReverted} patch(es) reverted in {hijackDll}" + (dllSkipped > 0 ? $", {dllSkipped} already original" : ""));
                }
                else
                {
                    Log($"  {hijackDll}: already original");
                }

                result.Succeeded = true;
                Log("Offline setup reverted.");
            }
            catch (Exception ex)
            {
                result.Fail($"Unexpected error: {ex.Message}");
                Log($"Error: {ex.Message}");
            }

            return result;
        }

        // SteamTools.exe deploys Core.dll -> xinput1_4.dll on every startup,
        // overwriting our core patches. Patch out DeployCoreToSteamDir (file
        // offset 0x282F0: push rbp -> ret) so it never runs.
        const int StExePatchOffset = 0x282F0;
        static readonly byte[] StExeOriginal = { 0x40, 0x55 }; // REX push rbp
        static readonly byte[] StExePatched  = { 0xC3, 0x90 }; // ret nop

        static string FindSteamToolsExe()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steamtools");
                var raw = key?.GetValue("SteamPath") as string;
                if (raw == null) return null;
                var path = Path.Combine(raw.Replace('/', '\\'), "SteamTools.exe");
                return File.Exists(path) ? path : null;
            }
            catch { return null; }
        }

        void KillSteamTools()
        {
            foreach (var p in Process.GetProcessesByName("SteamTools"))
            {
                try
                {
                    Log($"  Killing SteamTools.exe (PID {p.Id})...");
                    p.Kill();
                    p.WaitForExit(5000);
                }
                catch { }
                finally { p.Dispose(); }
            }
        }

        // 0 = already patched, 1 = needs patch, -1 = not found / unrecognized
        public int GetSteamToolsExePatchState()
        {
            var exe = FindSteamToolsExe();
            if (exe == null) return -1;

            try
            {
                var data = ReadFileShared(exe);
                if (data.Length < StExePatchOffset + 2) return -1;

                if (data[StExePatchOffset] == StExePatched[0]
                    && data[StExePatchOffset + 1] == StExePatched[1])
                    return 0;

                if (data[StExePatchOffset] == StExeOriginal[0]
                    && data[StExePatchOffset + 1] == StExeOriginal[1])
                    return 1;

                return -1; // unknown bytes
            }
            catch { return -1; }
        }

        // Returns: 1 = patched (or already patched), 0 = not found (skip), -1 = failed
        public int PatchSteamToolsExe()
        {
            var exe = FindSteamToolsExe();
            if (exe == null)
            {
                Log("  SteamTools.exe not found — skipping");
                return 0;
            }

            try
            {
                var data = ReadFileShared(exe);
                if (data.Length < StExePatchOffset + 2)
                {
                    Log("  SteamTools.exe too small - unrecognized version");
                    return -1;
                }

                if (data[StExePatchOffset] == StExePatched[0]
                    && data[StExePatchOffset + 1] == StExePatched[1])
                {
                    Log("  SteamTools.exe: already patched");
                    return 1;
                }

                if (data[StExePatchOffset] != StExeOriginal[0]
                    || data[StExePatchOffset + 1] != StExeOriginal[1])
                {
                    Log($"  SteamTools.exe: unexpected bytes at patch site ({data[StExePatchOffset]:X2} {data[StExePatchOffset + 1]:X2}) - unrecognized version");
                    return -1;
                }

                Backup(exe);
                data[StExePatchOffset] = StExePatched[0];
                data[StExePatchOffset + 1] = StExePatched[1];

                try
                {
                    FileUtils.AtomicWriteAllBytes(exe, data);
                }
                catch (IOException)
                {
                    KillSteamTools();
                    FileUtils.AtomicWriteAllBytes(exe, data);
                }

                Log("  SteamTools.exe: patched (DLL deploy disabled)");
                return 1;
            }
            catch (UnauthorizedAccessException)
            {
                Log("  SteamTools.exe: access denied - run as administrator");
                return -1;
            }
            catch (IOException ex)
            {
                Log($"  SteamTools.exe: {ex.Message}");
                return -1;
            }
        }

        public bool UnpatchSteamToolsExe()
        {
            var exe = FindSteamToolsExe();
            if (exe == null) return false;

            try
            {
                var data = ReadFileShared(exe);
                if (data.Length < StExePatchOffset + 2) return false;

                if (data[StExePatchOffset] == StExeOriginal[0]
                    && data[StExePatchOffset + 1] == StExeOriginal[1])
                    return true; // already original

                if (data[StExePatchOffset] != StExePatched[0]
                    || data[StExePatchOffset + 1] != StExePatched[1])
                    return false; // unknown bytes

                data[StExePatchOffset] = StExeOriginal[0];
                data[StExePatchOffset + 1] = StExeOriginal[1];

                try
                {
                    FileUtils.AtomicWriteAllBytes(exe, data);
                }
                catch (IOException)
                {
                    KillSteamTools();
                    FileUtils.AtomicWriteAllBytes(exe, data);
                }

                Log("  SteamTools.exe: restored to original");
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                Log("  SteamTools.exe: access denied - run as administrator");
                return false;
            }
            catch (IOException ex)
            {
                Log($"  SteamTools.exe: {ex.Message}");
                return false;
            }
        }

        void Log(string msg)
        {
            if (_verbose) _log?.Invoke(msg);
        }

        string DeployEmbeddedPayload()
        {
            try
            {
                var cachePath = Fingerprint.GetExpectedCachePath(_steamPath);
                var dir = Path.GetDirectoryName(cachePath);
                if (!Directory.Exists(dir))
                    Directory.CreateDirectory(dir);

                using var stream = typeof(Patcher).Assembly
                    .GetManifestResourceStream("payload.cache");
                if (stream == null)
                {
                    Log("  Embedded payload not found in assembly");
                    return null;
                }

                using var fs = new FileStream(cachePath, FileMode.Create, FileAccess.Write);
                stream.CopyTo(fs);

                Log($"  Deployed to {cachePath}");
                return cachePath;
            }
            catch (Exception ex)
            {
                Log($"  Deploy failed: {ex.Message}");
                return null;
            }
        }

        void Backup(string path)
        {
            var orig = path + ".orig";
            if (!File.Exists(orig))
            {
                File.Copy(path, orig);
                Log($"  Original saved to {orig}");
            }

            var bak = path + ".bak";
            File.Copy(path, bak, overwrite: true);
            Log($"  Backed up to {bak}");
        }

        void ReEncryptAndWrite(string cachePath, byte[] patchedPayload, byte[] iv)
        {
            // The original IV is intentionally reused for re-encryption.
            // This is acceptable because:
            // 1. The payload is not a protocol message — it's a local cache file.
            // 2. SteamTools itself uses the same IV when writing the cache.
            // 3. Generating a new IV would change the file prefix and potentially
            //    confuse SteamTools' cache validation.
            Log("  Re-encrypting..");
            using var compMs = new MemoryStream();
            using (var zOut = new ZLibStream(compMs, CompressionLevel.Optimal, leaveOpen: true))
                zOut.Write(patchedPayload, 0, patchedPayload.Length);

            var blob = new byte[4 + compMs.Length];
            BitConverter.TryWriteBytes(blob.AsSpan(0, 4), patchedPayload.Length);
            compMs.GetBuffer().AsSpan(0, (int)compMs.Length).CopyTo(blob.AsSpan(4));

            var newCt = PayloadCrypto.AesCbcEncrypt(blob, AesKey, iv);
            var output = new byte[16 + newCt.Length];
            iv.CopyTo(output, 0);
            newCt.CopyTo(output, 16);
            FileUtils.AtomicWriteAllBytes(cachePath, output);
            _cachedPayload = null;
        }

        // build the cloud redirect code cave with correct relative offsets
        static byte[] BuildDynamicCloudRedirectCave(int caveRva, int sendPktRva,
            int loadLibAIatRva, int getProcAddrIatRva, int recvPktGlobalRva)
        {
            var cave = (byte[])CloudRedirectCaveContent.Clone();

            int loadLibDisp = loadLibAIatRva - (caveRva + 0x16);
            BitConverter.TryWriteBytes(cave.AsSpan(0x12, 4), loadLibDisp);

            int getProcDisp = getProcAddrIatRva - (caveRva + 0x2B);
            BitConverter.TryWriteBytes(cave.AsSpan(0x27, 4), getProcDisp);

            int recvPktDisp = recvPktGlobalRva - (caveRva + 0x49);
            BitConverter.TryWriteBytes(cave.AsSpan(0x45, 4), recvPktDisp);

            int jumpBackDisp = (sendPktRva + 5) - (caveRva + 0x62);
            BitConverter.TryWriteBytes(cave.AsSpan(0x5E, 4), jumpBackDisp);

            return cave;
        }

        static bool BytesMatch(byte[] data, int dataOffset, byte[] pattern, int patOffset, int length)
        {
            if (dataOffset + length > data.Length) return false;
            for (int i = 0; i < length; i++)
                if (data[dataOffset + i] != pattern[patOffset + i]) return false;
            return true;
        }

        static string SafeHexDump(byte[] data, int offset, int length)
        {
            if (offset < 0 || offset >= data.Length) return "(out of bounds)";
            int available = Math.Min(length, data.Length - offset);
            return BitConverter.ToString(data, offset, available);
        }

        static (byte[] data, int applied, int skipped, List<string> errors) CheckPatches(byte[] data, PatchEntry[] patches)
        {
            int applied = 0, skipped = 0;
            var errors = new List<string>();

            foreach (var p in patches)
            {
                if (BytesMatch(data, p.Offset, p.Replacement, 0, p.Replacement.Length))
                    skipped++;
                else if (BytesMatch(data, p.Offset, p.Original, 0, p.Original.Length))
                    applied++;
                else
                    errors.Add($"  Mismatch at 0x{p.Offset:X}: expected {BitConverter.ToString(p.Original)}, got {SafeHexDump(data, p.Offset, p.Original.Length)}");
            }

            return (data, applied, skipped, errors);
        }

        static (byte[] data, int applied, int skipped, List<string> errors) ApplyPatches(byte[] data, PatchEntry[] patches)
        {
            var buf = (byte[])data.Clone();
            int applied = 0, skipped = 0;
            var errors = new List<string>();

            foreach (var p in patches)
            {
                if (BytesMatch(buf, p.Offset, p.Replacement, 0, p.Replacement.Length))
                {
                    skipped++;
                }
                else if (BytesMatch(buf, p.Offset, p.Original, 0, p.Original.Length))
                {
                    Buffer.BlockCopy(p.Replacement, 0, buf, p.Offset, p.Replacement.Length);
                    applied++;
                }
                else
                {
                    errors.Add($"  Mismatch at 0x{p.Offset:X}: expected {BitConverter.ToString(p.Original)}, got {SafeHexDump(buf, p.Offset, p.Original.Length)}");
                }
            }

            return (buf, applied, skipped, errors);
        }

        static (byte[] data, int reverted, int skipped, List<string> errors) UnapplyPatches(byte[] data, PatchEntry[] patches)
        {
            var buf = (byte[])data.Clone();
            int reverted = 0, skipped = 0;
            var errors = new List<string>();

            foreach (var p in patches)
            {
                if (BytesMatch(buf, p.Offset, p.Original, 0, p.Original.Length))
                {
                    skipped++;
                }
                else if (BytesMatch(buf, p.Offset, p.Replacement, 0, p.Replacement.Length))
                {
                    Buffer.BlockCopy(p.Original, 0, buf, p.Offset, p.Original.Length);
                    reverted++;
                }
                else
                {
                    errors.Add($"  Mismatch at 0x{p.Offset:X}: expected {BitConverter.ToString(p.Replacement)}, got {SafeHexDump(buf, p.Offset, p.Replacement.Length)}");
                }
            }

            return (buf, reverted, skipped, errors);
        }

        PatchEntry[] ResolveCorePatchOffsets(byte[] dll)
        {
            var sections = PeSection.Parse(dll);
            var rdataSec = PeSection.Find(sections, ".rdata");
            if (rdataSec == null)
            {
                Log("  Core.dll: no .rdata section found");
                return null;
            }

            int keyOffset = Signatures.ScanForBytes(dll, (int)rdataSec.Value.RawOffset,
                (int)(rdataSec.Value.RawOffset + rdataSec.Value.RawSize), AesKey);
            if (keyOffset < 0)
                keyOffset = Signatures.ScanForBytes(dll, 0, dll.Length, AesKey);
            if (keyOffset < 0)
            {
                Log("  Core.dll: AES key not found - not a recognized SteamTools version");
                return null;
            }
            Log($"  AES key found at 0x{keyOffset:X}");

            var textSec = PeSection.Find(sections, ".text");
            if (textSec == null)
            {
                Log("  Core.dll: no .text section found");
                return null;
            }
            int tStart = (int)textSec.Value.RawOffset;
            int tEnd = Math.Min(tStart + (int)textSec.Value.RawSize, dll.Length);

            return Signatures.ResolvePatternGroup(dll, Signatures.CorePatchDefs,
                tStart, tEnd, 0, 0, _verbose ? _log : null);
        }

        bool ResolvePayloadSections(byte[] payload, out PeSection[] sections,
            out int tStart, out int tEnd, out int gStart, out int gEnd)
        {
            tStart = tEnd = gStart = gEnd = 0;
            sections = PeSection.Parse(payload);

            Log($"  Payload PE: {sections.Length} sections, file size=0x{payload.Length:X}");
            foreach (var sec in sections)
                Log($"    '{sec.Name}': VA=0x{sec.VirtualAddress:X} VSize=0x{sec.VirtualSize:X} Raw=0x{sec.RawOffset:X} RawSize=0x{sec.RawSize:X} Chars=0x{sec.Characteristics:X8}");

            var textSec = PeSection.Find(sections, ".text");

            var knownNames = new HashSet<string> { ".text", ".rdata", ".data", ".pdata", ".fptable", ".rsrc", ".reloc" };
            PeSection? obfSec = null;
            foreach (var sec in sections)
            {
                if (!knownNames.Contains(sec.Name))
                {
                    obfSec = sec;
                    break;
                }
            }

            if (textSec == null || obfSec == null)
            {
                Log("  Payload: missing expected sections");
                return false;
            }

            tStart = (int)textSec.Value.RawOffset;
            tEnd = Math.Min(tStart + (int)textSec.Value.RawSize, payload.Length);
            gStart = (int)obfSec.Value.RawOffset;
            gEnd = Math.Min(gStart + (int)obfSec.Value.RawSize, payload.Length);
            return true;
        }

        PatchEntry[] ResolvePayloadPatchOffsets(byte[] payload)
        {
            if (!ResolvePayloadSections(payload, out _, out int tStart, out int tEnd, out int gStart, out int gEnd))
                return null;

            return Signatures.ResolvePatternGroup(payload, Signatures.PayloadP123Defs,
                tStart, tEnd, gStart, gEnd, _verbose ? _log : null);
        }

        PatchEntry[] ResolveSetupPatchOffsets(byte[] payload)
        {
            if (!ResolvePayloadSections(payload, out _, out int tStart, out int tEnd, out int gStart, out int gEnd))
                return null;

            return Signatures.ResolvePatternGroup(payload, Signatures.PayloadSetupDefs,
                tStart, tEnd, gStart, gEnd, _verbose ? _log : null);
        }

        CloudRedirectResolveResult ResolveCloudRedirectPatchOffsets(byte[] payload)
        {
            if (!ResolvePayloadSections(payload, out var sections, out int tStart, out int tEnd, out int gStart, out int gEnd))
                return null;

            int sendPkt = Signatures.FindSendPktFunction(payload, tStart, tEnd);
            if (sendPkt < 0)
            {
                Log("  Payload: could not locate SendPkt function by pattern");
                return null;
            }

            byte[] sendPktOriginal = { 0x48, 0x89, 0x5C, 0x24, 0x20 };
            bool isOriginal = BytesMatch(payload, sendPkt, sendPktOriginal, 0, 5);
            bool isAlreadyJmp = payload[sendPkt] == 0xE9;

            if (!isOriginal && !isAlreadyJmp)
            {
                Log($"  Payload: unexpected bytes at SendPkt (0x{sendPkt:X}): {SafeHexDump(payload, sendPkt, 5)}");
                return null;
            }

            int sendPktRva = PeSection.FileOffsetToRva(sections, sendPkt);
            if (sendPktRva < 0)
            {
                Log($"  Payload: RVA resolution failed for SendPkt (file=0x{sendPkt:X})");
                return null;
            }

            int caveFileOffset;
            if (isAlreadyJmp)
            {
                // Decode existing jmp to find where the cave was placed last time
                int existingDisp = BitConverter.ToInt32(payload, sendPkt + 1);
                int existingCaveRva = sendPktRva + 5 + existingDisp;
                caveFileOffset = PeSection.RvaToFileOffset(sections, existingCaveRva);
                if (caveFileOffset < 0)
                {
                    Log($"  Payload: existing jmp target RVA 0x{existingCaveRva:X} does not resolve to a file offset");
                    return null;
                }
            }
            else
            {
                caveFileOffset = Signatures.FindCodeCave(payload, sections, CloudRedirectCaveContent.Length);
                if (caveFileOffset < 0)
                {
                    Log("  Payload: could not find code cave in any executable section");
                    return null;
                }
            }

            int caveRva = PeSection.FileOffsetToRva(sections, caveFileOffset);

            if (caveRva < 0)
            {
                Log($"  Payload: RVA resolution failed for cave (file=0x{caveFileOffset:X})");
                return null;
            }

            var (loadLibIatRva, getProcIatRva) = PeImportParser.FindKernel32IatEntries(payload, sections);
            if (loadLibIatRva < 0 || getProcIatRva < 0)
            {
                Log($"  Payload: KERNEL32 IAT not found (LoadLib={loadLibIatRva:X}, GetProc={getProcIatRva:X})");
                return null;
            }

            // recvPktGlobal: scan obfuscated section for the hook installer's
            // lea rcx, sub_SendPkt -> then find mov cs:qword, rcx nearby
            int recvPktGlobalRva = Signatures.FindRecvPktGlobalRva(payload, sections,
                sendPktRva, gStart, gEnd);
            if (recvPktGlobalRva < 0)
            {
                Log("  Payload: could not locate recvPktGlobal by pattern");
                return null;
            }

            var recvPktSec = PeSection.FindByRva(sections, recvPktGlobalRva);
            if (recvPktSec == null)
            {
                Log($"  Payload: recvPktGlobalRva 0x{recvPktGlobalRva:X} does not map to any PE section");
                foreach (var sec in sections)
                    Log($"    Section '{sec.Name}': VA=0x{sec.VirtualAddress:X} VSize=0x{sec.VirtualSize:X} Raw=0x{sec.RawOffset:X} RawSize=0x{sec.RawSize:X}");
                return null;
            }
            Log($"  recvPktGlobal RVA 0x{recvPktGlobalRva:X} -> section '{recvPktSec.Value.Name}'");

            var sendPktOrig = new byte[5];
            if (isOriginal)
                Buffer.BlockCopy(payload, sendPkt, sendPktOrig, 0, 5);
            else
                Buffer.BlockCopy(sendPktOriginal, 0, sendPktOrig, 0, 5);

            int jmpTarget = caveRva;
            int jmpDisp = jmpTarget - (sendPktRva + 5);
            var sendPktRepl = new byte[5];
            sendPktRepl[0] = 0xE9;
            BitConverter.TryWriteBytes(sendPktRepl.AsSpan(1, 4), jmpDisp);

            var dynamicCave = BuildDynamicCloudRedirectCave(caveRva, sendPktRva,
                loadLibIatRva, getProcIatRva, recvPktGlobalRva);

            Log($"  CloudRedirect: SendPkt at file=0x{sendPkt:X} rva=0x{sendPktRva:X}");
            Log($"  CloudRedirect: cave at file=0x{caveFileOffset:X} rva=0x{caveRva:X}");
            Log($"  IAT: LoadLibraryA=0x{loadLibIatRva:X}, GetProcAddress=0x{getProcIatRva:X}");

            var patches = new List<PatchEntry>
            {
                new PatchEntry(sendPkt, sendPktOrig, sendPktRepl),
            };

            return new CloudRedirectResolveResult
            {
                Patches = patches.ToArray(),
                DynamicCodeCave = dynamicCave,
                CodeCaveFileOffset = caveFileOffset,
            };
        }

        string DeployCloudRedirect()
        {
            var dllDest = Path.Combine(_steamPath, "cloud_redirect.dll");
            var error = EmbeddedDll.DeployTo(dllDest);
            if (error != null)
                return error;

            Log($"  Deployed cloud_redirect.dll to {_steamPath}");
            return null;
        }



        /// <summary>
        /// Namespace mode: applies core DLL patches + P1/P2/P3 (disabling SteamTools'
        /// native cloud redirect) + CloudRedirect code cave (so our DLL handles both
        /// appid rewriting to proxy app and filename namespacing).
        /// </summary>
        public PatchResult ApplyCloudRedirectNamespace()
        {
            _verbose = true;
            var result = new PatchResult();

            var version = SteamDetector.GetSteamVersion(_steamPath);
            if (version == null)
            {
                Log("  WARNING: Could not read Steam version from manifest");
                return result.Fail("Steam version could not be determined. Cannot safely patch.");
            }
            if (version.Value != SteamDetector.ExpectedSteamVersion)
            {
                Log($"  Steam version: {version.Value} (UNSUPPORTED)");
                Log($"  Expected version: {SteamDetector.ExpectedSteamVersion}");
                return result.Fail(
                    $"Steam version mismatch: installed {version.Value}, " +
                    $"expected {SteamDetector.ExpectedSteamVersion}. " +
                    "Patching an unsupported version risks corrupting steamclient64.dll. " +
                    "Update CloudRedirect or downgrade Steam.");
            }
            Log($"  Steam version: {version.Value} (OK)");

            try
            {
                var hijackDll = FindCoreDll();
                if (hijackDll == null)
                    return result.Fail("SteamTools Core DLL not found. Is SteamTools installed?");

                var dllPath = Path.Combine(_steamPath, hijackDll);
                byte[] dllData;
                try { dllData = ReadFileShared(dllPath); }
                catch (IOException) { return result.Fail($"{hijackDll} is in use - close Steam first"); }

                var resolvedCore = ResolveCorePatchOffsets(dllData);
                if (resolvedCore == null)
                    return result.Fail($"Could not identify patch locations in {hijackDll} - unsupported version?");

                var (patchedDll, dllApplied, dllSkipped, dllErrors) = ApplyPatches(dllData, resolvedCore);
                if (dllErrors.Count > 0)
                {
                    foreach (var err in dllErrors) Log(err);
                    return result.Fail("Byte mismatch in " + hijackDll + " - wrong version?");
                }

                var cachePath = Fingerprint.FindCachePath(_steamPath, log: _log);
                if (cachePath == null)
                {
                    Log("Payload cache not found. Deploying embedded payload..");
                    cachePath = DeployEmbeddedPayload();
                    if (cachePath == null)
                        return result.Fail("Could not deploy payload cache.");
                }

                Log("Patching payload (CloudRedirect namespace mode)..");
                Backup(cachePath);

                var (payload, iv, plErr) = ReadAndDecryptPayload(cachePath);
                if (payload == null)
                    return result.Fail(plErr);

                var resolvedPayload = ResolvePayloadPatchOffsets(payload);
                byte[] afterP123 = payload;
                if (resolvedPayload != null)
                {
                    var (patched, p123Applied, p123Skipped, p123Errors) = ApplyPatches(payload, resolvedPayload);
                    if (p123Errors.Count > 0)
                    {
                        foreach (var err in p123Errors) Log(err);
                        // P1/P2/P3 errors are non-fatal: these patches disable SteamTools'
                        // built-in cloud redirect. If they fail (e.g. SteamTools version mismatch),
                        // CloudRedirect's namespace hooks still work — the SteamTools redirect
                        // and ours will simply coexist (our hooks take priority).
                        Log("  Warning: could not apply some P1/P2/P3 patches (continuing — non-fatal)");
                    }
                    if (p123Applied > 0)
                        Log($"  Applied {p123Applied} cloud-disable patch(es) (P1/P2/P3)");
                    else if (p123Skipped == resolvedPayload.Length)
                        Log("  P1/P2/P3: already applied (SteamTools cloud redirect disabled)");
                    afterP123 = patched;
                }
                else
                {
                    Log("  Could not resolve P1/P2/P3 offsets (continuing without them)");
                }

                var resolved = ResolveCloudRedirectPatchOffsets(afterP123);
                if (resolved == null)
                    return result.Fail("Could not locate CloudRedirect patch sites in payload");

                var (patchedPayload, plApplied, plSkipped, plErrors) = ApplyPatches(afterP123, resolved.Patches);
                if (plErrors.Count > 0)
                {
                    foreach (var err in plErrors) Log(err);
                    return result.Fail("Byte mismatch at CloudRedirect patch sites");
                }

                if (resolved.CodeCaveFileOffset + resolved.DynamicCodeCave.Length > patchedPayload.Length)
                    return result.Fail("Payload too small for code cave injection");

                bool caveAlready = BytesMatch(patchedPayload, resolved.CodeCaveFileOffset,
                    resolved.DynamicCodeCave, 0, resolved.DynamicCodeCave.Length);

                var deployErr = DeployCloudRedirect();
                if (deployErr != null)
                    return result.Fail(deployErr);

                // Write payload first (less dangerous if interrupted mid-write)
                Buffer.BlockCopy(resolved.DynamicCodeCave, 0, patchedPayload,
                    resolved.CodeCaveFileOffset, resolved.DynamicCodeCave.Length);
                ReEncryptAndWrite(cachePath, patchedPayload, iv);
                int total = plApplied + (caveAlready ? 0 : 1);
                Log($"  {total} cave change(s) applied" + (plSkipped > 0 ? $", {plSkipped} already done" : ""));
                result.CachePatched = true;

                Backup(dllPath);
                if (dllApplied > 0)
                {
                    FileUtils.AtomicWriteAllBytes(dllPath, patchedDll);
                    Log($"  {dllApplied} core patch(es) applied to {hijackDll}");
                }
                result.DllPatched = true;

                result.Succeeded = true;
                Log("Done. P1/P2/P3 applied (SteamTools redirect disabled) + namespace DLL will be loaded.");
            }
            catch (Exception ex)
            {
                result.Fail($"Unexpected error: {ex.Message}");
                Log($"Error: {ex.Message}");
            }

            return result;
        }

        public PatchResult RevertCloudRedirectNamespace()
        {
            _verbose = true;
            var result = new PatchResult();

            try
            {
                var hijackDll = FindCoreDll();
                if (hijackDll == null)
                    return result.Fail("SteamTools Core DLL not found.");

                var dllPath = Path.Combine(_steamPath, hijackDll);
                byte[] dllData;
                try { dllData = ReadFileShared(dllPath); }
                catch (IOException) { return result.Fail($"{hijackDll} is in use - close Steam first"); }

                var resolvedCore = ResolveCorePatchOffsets(dllData);
                if (resolvedCore == null)
                    return result.Fail($"Could not identify patch locations in {hijackDll}");

                var (revertedDll, dllReverted, dllSkipped, dllErrors) = UnapplyPatches(dllData, resolvedCore);
                if (dllErrors.Count > 0)
                {
                    foreach (var err in dllErrors) Log(err);
                    return result.Fail("Byte mismatch in " + hijackDll);
                }

                var cachePath = Fingerprint.FindCachePath(_steamPath, verbose: false, log: _log);
                if (cachePath == null)
                    return result.Fail("Payload cache not found.");

                var (payload, iv, plErr) = ReadAndDecryptPayload(cachePath);
                if (payload == null)
                    return result.Fail(plErr);

                // Revert SendPkt hook (CloudRedirect-specific patch)
                var resolved = ResolveCloudRedirectPatchOffsets(payload);
                byte[] afterCrRevert = payload;
                if (resolved != null)
                {
                    var (reverted, crReverted, crSkipped, crErrors) = UnapplyPatches(payload, resolved.Patches);
                    if (crErrors.Count > 0)
                    {
                        foreach (var err in crErrors) Log(err);
                        return result.Fail("Byte mismatch at CloudRedirect patch sites");
                    }
                    if (crReverted > 0)
                        Log($"  Reverted {crReverted} CloudRedirect hook patch(es)");
                    else
                        Log("  CloudRedirect hook: already original");
                    afterCrRevert = reverted;
                }

                // Revert P1/P2/P3 patches
                var resolvedPayload = ResolvePayloadPatchOffsets(afterCrRevert);
                byte[] afterP123Revert = afterCrRevert;
                if (resolvedPayload != null)
                {
                    var (reverted, p123Reverted, p123Skipped, p123Errors) = UnapplyPatches(afterCrRevert, resolvedPayload);
                    if (p123Errors.Count > 0)
                    {
                        foreach (var err in p123Errors) Log(err);
                        Log("  Warning: could not revert some P1/P2/P3 patches");
                    }
                    if (p123Reverted > 0)
                        Log($"  Reverted {p123Reverted} P1/P2/P3 patch(es)");
                    else if (p123Skipped == resolvedPayload.Length)
                        Log("  P1/P2/P3: already original");
                    afterP123Revert = reverted;
                }

                // Write files (payload first, DLL second — matches apply order)
                Backup(cachePath);
                ReEncryptAndWrite(cachePath, afterP123Revert, iv);
                Log("  Payload written.");

                if (dllReverted > 0)
                {
                    Backup(dllPath);
                    FileUtils.AtomicWriteAllBytes(dllPath, revertedDll);
                    Log($"  {dllReverted} core patch(es) reverted in {hijackDll}");
                }
                else
                {
                    Log($"  {hijackDll}: already original");
                }

                result.Succeeded = true;
                Log("Cloud redirect patch reverted.");
            }
            catch (Exception ex)
            {
                result.Fail($"Unexpected error: {ex.Message}");
                Log($"Error: {ex.Message}");
            }

            return result;
        }
    }
}
