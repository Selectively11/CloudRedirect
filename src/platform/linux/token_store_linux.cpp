// Token storage for Linux: libsecret with 0600 file fallback.

#include "cloud_provider_base.h"
#include "log.h"

#include <fstream>
#include <filesystem>
#include <mutex>
#include <memory>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>

// ── libsecret runtime binding (dlopen, no compile-time dependency) ──────

typedef void* GCancellable;
typedef struct _GError { int domain; int code; char* message; } GError;
typedef struct _SecretSchema {
    const char* name;
    int flags;
    struct { const char* name; int type; } attributes[32];
} SecretSchema;

typedef char* (*secret_password_lookup_sync_fn)(const SecretSchema*, GCancellable*, GError**, ...);
typedef int (*secret_password_store_sync_fn)(const SecretSchema*, const char*, const char*, const char*, GCancellable*, GError**, ...);
typedef void (*secret_password_free_fn)(char*);
typedef void (*g_error_free_fn)(GError*);

static void* g_libsecret = nullptr;
static void* g_libglib = nullptr;
static secret_password_lookup_sync_fn secret_password_lookup_sync = nullptr;
static secret_password_store_sync_fn secret_password_store_sync = nullptr;
static secret_password_free_fn secret_password_free = nullptr;
static g_error_free_fn g_error_free = nullptr;
static bool g_secretServiceAvailable = false;
static std::once_flag g_secretInitOnce;

static SecretSchema g_tokenSchema = {
    "io.github.cloudredirect.Token",
    0, // SECRET_SCHEMA_NONE
    {
        { "provider", 0 }, // SECRET_SCHEMA_ATTRIBUTE_STRING
        { "account", 0 },
        { nullptr, 0 }
    }
};

static void InitSecretService() {
#if defined(__i386__)
    LOG("[TokenStorage] Secret Service unavailable in 32-bit Steam process; using file fallback");
    return;
#endif

    g_libsecret = dlopen("libsecret-1.so.0", RTLD_NOW | RTLD_LOCAL);
    if (!g_libsecret) {
        LOG("[TokenStorage] libsecret not available: %s", dlerror());
        return;
    }
    
    g_libglib = dlopen("libglib-2.0.so.0", RTLD_NOW | RTLD_LOCAL);
    if (!g_libglib) {
        LOG("[TokenStorage] libglib not available: %s", dlerror());
        dlclose(g_libsecret);
        g_libsecret = nullptr;
        return;
    }
    
    secret_password_lookup_sync = (secret_password_lookup_sync_fn)dlsym(g_libsecret, "secret_password_lookup_sync");
    secret_password_store_sync = (secret_password_store_sync_fn)dlsym(g_libsecret, "secret_password_store_sync");
    secret_password_free = (secret_password_free_fn)dlsym(g_libsecret, "secret_password_free");
    g_error_free = (g_error_free_fn)dlsym(g_libglib, "g_error_free");
    
    if (!secret_password_lookup_sync || !secret_password_store_sync || 
        !secret_password_free || !g_error_free) {
        LOG("[TokenStorage] Failed to resolve libsecret symbols");
        dlclose(g_libsecret);
        dlclose(g_libglib);
        g_libsecret = nullptr;
        g_libglib = nullptr;
        return;
    }
    
    g_secretServiceAvailable = true;
    LOG("[TokenStorage] libsecret available, using Secret Service for token storage");
}

// Parse "tokens_gdrive.json" -> provider="gdrive", account from path
static bool ParseTokenPath(const std::string& path, std::string& provider, std::string& account) {
    auto filename = std::filesystem::path(path).stem().string();
    auto sep = filename.find('_');
    if (sep == std::string::npos) return false;
    provider = filename.substr(0, sep);
    account = filename.substr(sep + 1);
    return !provider.empty() && !account.empty();
}

static std::string ReadTokenFromSecretService(const std::string& provider, const std::string& account) {
    std::call_once(g_secretInitOnce, InitSecretService);
    if (!g_secretServiceAvailable) return {};
    
    GError* error = nullptr;
    char* password = secret_password_lookup_sync(
        &g_tokenSchema, nullptr, &error,
        "provider", provider.c_str(),
        "account", account.c_str(),
        nullptr);
    
    if (error) {
        LOG("[TokenStorage] Secret Service lookup failed: %s", error->message);
        g_error_free(error);
        return {};
    }
    
    if (!password) return {};
    
    std::string result(password);
    secret_password_free(password);
    return result;
}

static bool WriteTokenToSecretService(const std::string& provider, const std::string& account, 
                                       const std::string& json) {
    std::call_once(g_secretInitOnce, InitSecretService);
    if (!g_secretServiceAvailable) return false;
    
    GError* error = nullptr;
    std::string label = "CloudRedirect " + provider + " token";
    
    int ok = secret_password_store_sync(
        &g_tokenSchema, "default", label.c_str(), json.c_str(),
        nullptr, &error,
        "provider", provider.c_str(),
        "account", account.c_str(),
        nullptr);
    
    if (error) {
        LOG("[TokenStorage] Secret Service store failed: %s", error->message);
        g_error_free(error);
        return false;
    }
    
    return ok != 0;
}

// ── Plaintext file fallback (0600 perms) ───────────────────────────────

static std::string ReadTokenFileFallback(const std::string& path, std::string& outError) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        outError = "file does not exist";
        return {};
    }
    if (!S_ISREG(st.st_mode)) {
        outError = "path is not a regular file";
        return {};
    }
    if (access(path.c_str(), R_OK) != 0) {
        outError = "permission denied (cannot read)";
        return {};
    }
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        outError = "failed to open file";
        return {};
    }
    std::string raw((std::istreambuf_iterator<char>(f)), {});
    f.close();
    if (raw.empty()) {
        outError = "file is empty";
        return {};
    }
    outError.clear();
    return raw;
}

static bool WriteTokenFileFallback(const std::string& path, const std::string& json) {
    auto parent = std::filesystem::path(path).parent_path();
    std::error_code ec;
    std::filesystem::create_directories(parent, ec);

    std::string tempPath = path + ".tmp";
    int fd = open(tempPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return false;

    size_t written = 0;
    while (written < json.size()) {
        ssize_t n = write(fd, json.data() + written, json.size() - written);
        if (n < 0) { ::close(fd); unlink(tempPath.c_str()); return false; }
        written += n;
    }
    ::close(fd);

    if (rename(tempPath.c_str(), path.c_str()) != 0) {
        unlink(tempPath.c_str());
        return false;
    }
    return true;
}

// ── LinuxTokenStore ────────────────────────────────────────────────────

class LinuxTokenStore : public ITokenStore {
public:
    std::string Read(const std::string& path) override {
        std::string provider, account;
        if (ParseTokenPath(path, provider, account)) {
            auto secret = ReadTokenFromSecretService(provider, account);
            if (!secret.empty()) {
                LOG("[TokenStorage] Loaded token from Secret Service (%s)", provider.c_str());
                return secret;
            }
        }
        std::string error;
        auto content = ReadTokenFileFallback(path, error);
        if (content.empty() && !error.empty()) {
            LOG("[TokenStorage] Cannot read %s: %s", path.c_str(), error.c_str());
        }
        return content;
    }

    bool Write(const std::string& path, const std::string& json) override {
        std::string provider, account;
        if (ParseTokenPath(path, provider, account)) {
            if (WriteTokenToSecretService(provider, account, json)) {
                LOG("[TokenStorage] Stored token in Secret Service (%s)", provider.c_str());
                // Keep the plaintext file as well — the UI checks its existence
                // for auth status, and it serves as a fallback if Secret Service
                // is unavailable on next boot.
                return WriteTokenFileFallback(path, json);
            }
        }
        return WriteTokenFileFallback(path, json);
    }

    bool IsEncryptionAvailable() const override {
        std::call_once(g_secretInitOnce, InitSecretService);
        return g_secretServiceAvailable;
    }
};

// Factory function
std::unique_ptr<ITokenStore> CreateTokenStore() {
    return std::make_unique<LinuxTokenStore>();
}
