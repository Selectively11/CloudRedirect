
#include "cloud_provider_base.h"
#include "log.h"

#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <memory>
#include <mutex>
#include <string>
#include <unistd.h>
#include <vector>

static constexpr size_t kMaxResponseSize = 64 * 1024 * 1024;

// libcurl C API typedefs
typedef void CURL;
typedef int CURLcode;
typedef int CURLoption;

#define CURLOPT_URL            10002
#define CURLOPT_WRITEFUNCTION  20011
#define CURLOPT_WRITEDATA      10001
#define CURLOPT_HTTPHEADER     10023
#define CURLOPT_POSTFIELDS     10015
#define CURLOPT_POSTFIELDSIZE  60
#define CURLOPT_CUSTOMREQUEST  10036
#define CURLOPT_NOBODY         44
#define CURLOPT_TIMEOUT        13
#define CURLOPT_CONNECTTIMEOUT 78
#define CURLOPT_USERAGENT      10018
#define CURLOPT_FOLLOWLOCATION 52
#define CURLOPT_MAXREDIRS      68
#define CURLOPT_HEADERFUNCTION 20079
#define CURLOPT_HEADERDATA     10029
#define CURLOPT_SSL_VERIFYPEER 64
#define CURLOPT_SSL_VERIFYHOST 81
#define CURLOPT_CAINFO         10065
#define CURLINFO_RESPONSE_CODE 0x200002

typedef int  (*curl_global_init_fn)(long);
typedef CURL* (*curl_easy_init_fn)(void);
typedef CURLcode (*curl_easy_setopt_fn)(CURL*, CURLoption, ...);
typedef CURLcode (*curl_easy_perform_fn)(CURL*);
typedef CURLcode (*curl_easy_getinfo_fn)(CURL*, int, ...);
typedef void (*curl_easy_cleanup_fn)(CURL*);
typedef struct curl_slist* (*curl_slist_append_fn)(struct curl_slist*, const char*);
typedef void (*curl_slist_free_all_fn)(struct curl_slist*);

#define CURL_GLOBAL_ALL 3  // CURL_GLOBAL_SSL | CURL_GLOBAL_WIN32

struct CurlAPI {
    void* handle = nullptr;
    curl_global_init_fn global_init = nullptr;
    curl_easy_init_fn easy_init = nullptr;
    curl_easy_setopt_fn easy_setopt = nullptr;
    curl_easy_perform_fn easy_perform = nullptr;
    curl_easy_getinfo_fn easy_getinfo = nullptr;
    curl_easy_cleanup_fn easy_cleanup = nullptr;
    curl_slist_append_fn slist_append = nullptr;
    curl_slist_free_all_fn slist_free_all = nullptr;
};

static CurlAPI g_curl{};
static bool g_curlInitAttempted = false;
static std::mutex g_curlInitMutex;

// 32-bit libcurl: curl_easy_init/cleanup race shared SSL tables.
// Guard handle lifecycle (not perform) under mutex.
static std::mutex g_curlHandleMutex;

static bool InitCurl() {
    // Serialize init and call curl_global_init() explicitly here -- libcurl's lazy
    // global init off the first curl_easy_init isn't thread-safe and crashed when
    // EndSession raced a background worker.
    std::lock_guard<std::mutex> lock(g_curlInitMutex);
    if (g_curlInitAttempted) return g_curl.handle != nullptr;
    g_curlInitAttempted = true;

    const char* names[] = {
        "libcurl.so.4", "libcurl.so", "libcurl-gnutls.so.4",
        "libcurl-gnutls.so", "libcurl-nss.so.4", nullptr
    };

    // Ensure 32-bit lib paths are searchable
    const char* ldPath = getenv("LD_LIBRARY_PATH");
    if (ldPath) {
        std::string path(ldPath);
        if (path.find("/usr/lib32") == std::string::npos) {
            path += ":/usr/lib32:/usr/lib/i386-linux-gnu:/usr/lib";
            setenv("LD_LIBRARY_PATH", path.c_str(), 1);
        }
    }

    for (int i = 0; names[i]; i++) {
        g_curl.handle = dlopen(names[i], RTLD_NOW | RTLD_GLOBAL);
        if (g_curl.handle) {
            LOG("[HTTP] Loaded %s", names[i]);
            break;
        }
    }

    if (!g_curl.handle) {
        LOG("[HTTP] Failed to load libcurl: %s", dlerror());
        return false;
    }

    g_curl.global_init  = (curl_global_init_fn)dlsym(g_curl.handle, "curl_global_init");
    g_curl.easy_init    = (curl_easy_init_fn)dlsym(g_curl.handle, "curl_easy_init");
    g_curl.easy_setopt  = (curl_easy_setopt_fn)dlsym(g_curl.handle, "curl_easy_setopt");
    g_curl.easy_perform = (curl_easy_perform_fn)dlsym(g_curl.handle, "curl_easy_perform");
    g_curl.easy_getinfo = (curl_easy_getinfo_fn)dlsym(g_curl.handle, "curl_easy_getinfo");
    g_curl.easy_cleanup = (curl_easy_cleanup_fn)dlsym(g_curl.handle, "curl_easy_cleanup");
    g_curl.slist_append = (curl_slist_append_fn)dlsym(g_curl.handle, "curl_slist_append");
    g_curl.slist_free_all = (curl_slist_free_all_fn)dlsym(g_curl.handle, "curl_slist_free_all");

    if (!g_curl.easy_init || !g_curl.easy_setopt || !g_curl.easy_perform ||
        !g_curl.easy_getinfo || !g_curl.easy_cleanup) {
        LOG("[HTTP] libcurl missing required symbols");
        dlclose(g_curl.handle);
        g_curl.handle = nullptr;
        return false;
    }

    // Explicit global init (once, under the mutex) -- required before any
    // curl_easy_init and must not be left to libcurl's non-thread-safe lazy path.
    if (g_curl.global_init) {
        g_curl.global_init(CURL_GLOBAL_ALL);
        LOG("[HTTP] curl_global_init done");
    } else {
        LOG("[HTTP] WARNING: curl_global_init symbol missing; relying on lazy init");
    }

    return true;
}

static size_t WriteCallback(const char* data, size_t size, size_t nmemb, std::string* out) {
    size_t total = size * nmemb;
    if (out->size() + total > kMaxResponseSize) return 0;
    out->append(data, total);
    return total;
}

static size_t HeaderCallback(const char* data, size_t size, size_t nmemb, std::string* out) {
    size_t total = size * nmemb;
    out->append(data, total);
    return total;
}

// Extract Location header from raw header block
static std::string ExtractLocation(const std::string& headers) {
    for (const char* key : {"Location: ", "location: "}) {
        size_t pos = headers.find(key);
        if (pos == std::string::npos) continue;
        pos += strlen(key);
        size_t end = headers.find("\r\n", pos);
        if (end == std::string::npos) end = headers.find("\n", pos);
        if (end != std::string::npos) return headers.substr(pos, end - pos);
    }
    return {};
}

// Parse the raw header block into a lower-cased name -> value map.
// Skips the HTTP status line and folds duplicate names to the last value.
static void ParseHeaders(const std::string& raw, std::map<std::string, std::string>& out) {
    size_t pos = 0;
    while (pos < raw.size()) {
        size_t eol = raw.find('\n', pos);
        std::string line = raw.substr(pos, (eol == std::string::npos ? raw.size() : eol) - pos);
        pos = (eol == std::string::npos) ? raw.size() : eol + 1;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;  // status line or blank
        std::string name = line.substr(0, colon);
        for (char& c : name) c = (char)tolower((unsigned char)c);
        size_t vs = colon + 1;
        while (vs < line.size() && (line[vs] == ' ' || line[vs] == '\t')) vs++;
        out[name] = line.substr(vs);
    }
}

static HttpUtil::HttpResp CurlRequest(const char* logTag, const char* method,
                                       const std::string& url, const std::string& body,
                                       const std::vector<std::string>& hdrs,
                                       long timeout, bool captureHeaders,
                                       std::string* outLocation,
                                       bool followRedirects = false,
                                       const TransportOptions* opts = nullptr) {
    HttpUtil::HttpResp resp;

    if (!InitCurl()) {
        LOG("%s libcurl not available", logTag);
        return resp;
    }

    bool allowHttp = opts && opts->allowInsecureHttp;
    if (url.substr(0, 8) != "https://" && !(allowHttp && url.substr(0, 7) == "http://")) {
        LOG("%s BLOCKED non-HTTPS: %s", logTag, url.c_str());
        return resp;
    }

    // Encode bare spaces in URL (libcurl rejects them with CURLE_URL_MALFORMAT)
    std::string safeUrl;
    safeUrl.reserve(url.size());
    for (char c : url) {
        if (c == ' ') safeUrl += "%20";
        else safeUrl += c;
    }

    CURL* curl;
    {
        std::lock_guard<std::mutex> lock(g_curlHandleMutex);
        curl = g_curl.easy_init();
    }
    if (!curl) return resp;

    std::string responseBody;
    std::string responseHeaders;

    g_curl.easy_setopt(curl, CURLOPT_URL, safeUrl.c_str());
    g_curl.easy_setopt(curl, CURLOPT_WRITEFUNCTION, (void*)WriteCallback);
    g_curl.easy_setopt(curl, CURLOPT_WRITEDATA, &responseBody);
    g_curl.easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
    g_curl.easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    g_curl.easy_setopt(curl, CURLOPT_USERAGENT, "CloudRedirect/1.0");
    // Follow redirects only on token-stripped requests (mirrors WinHTTP defaults).
    g_curl.easy_setopt(curl, CURLOPT_FOLLOWLOCATION, followRedirects ? 1L : 0L);
    if (followRedirects)
        g_curl.easy_setopt(curl, CURLOPT_MAXREDIRS, 10L);

    if (captureHeaders) {
        g_curl.easy_setopt(curl, CURLOPT_HEADERFUNCTION, (void*)HeaderCallback);
        g_curl.easy_setopt(curl, CURLOPT_HEADERDATA, &responseHeaders);
    }

    // TLS relaxation for self-hosted endpoints (self-signed / internal CA).
    if (opts) {
        if (opts->allowInsecureTls) {
            g_curl.easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
            g_curl.easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        } else if (!opts->caCertPath.empty()) {
            g_curl.easy_setopt(curl, CURLOPT_CAINFO, opts->caCertPath.c_str());
        }
    }

    if (strcmp(method, "GET") != 0)
        g_curl.easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);

    // Without NOBODY, HEAD blocks waiting for a body until the timeout fires.
    if (strcmp(method, "HEAD") == 0)
        g_curl.easy_setopt(curl, CURLOPT_NOBODY, 1L);

    if (!body.empty()) {
        g_curl.easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        g_curl.easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body.size());
    }

    struct curl_slist* slist = nullptr;
    if (g_curl.slist_append) {
        for (const auto& h : hdrs)
            slist = g_curl.slist_append(slist, h.c_str());
        if (slist)
            g_curl.easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
    }

    CURLcode res = g_curl.easy_perform(curl);

    long httpCode = 0;
    g_curl.easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    if (slist && g_curl.slist_free_all) g_curl.slist_free_all(slist);
    {
        std::lock_guard<std::mutex> lock(g_curlHandleMutex);
        g_curl.easy_cleanup(curl);
    }

    if (res != 0) {
        LOG("%s curl failed: %d (%s %s)", logTag, res, method, url.c_str());
        return resp;
    }

    resp.status = (int)httpCode;
    resp.body = std::move(responseBody);

    if (!responseHeaders.empty()) {
        std::string loc = ExtractLocation(responseHeaders);
        if (outLocation) *outLocation = loc;
        resp.location = std::move(loc);
        ParseHeaders(responseHeaders, resp.headers);
    }

    return resp;
}

class DlopenCurlTransport : public IHttpTransport {
public:
    explicit DlopenCurlTransport(const char* logTag) : m_logTag(logTag) {}

    bool Init() override { return InitCurl(); }
    void Shutdown() override {}
    bool IsReady() const override { return g_curl.handle != nullptr; }
    void SetOptions(const TransportOptions& opts) override { m_opts = opts; }

    HttpUtil::HttpResp Request(const char* method, const char* host,
                               const std::string& path, const std::string& body,
                               const std::vector<std::string>& headers) override {
        std::string url = Scheme() + host + path;
        return CurlRequest(m_logTag, method, url, body, headers, 30L, true, nullptr,
                           false, &m_opts);
    }

    HttpUtil::HttpResp RequestUrl(const char* method, const std::string& fullUrl,
                                   const std::string& body,
                                   const std::vector<std::string>& headers) override {
        return CurlRequest(m_logTag, method, fullUrl, body, headers, 60L, true, nullptr,
                           false, &m_opts);
    }

    HttpUtil::HttpResp AuthenticatedGetWithRedirect(const std::string& host,
                                                     const std::string& path,
                                                     const std::string& authHeader) override {
        std::string url = Scheme() + host + path;
        std::vector<std::string> hdrs = {authHeader};
        std::string location;
        auto resp = CurlRequest(m_logTag, "GET", url, {}, hdrs, 30L, true, &location,
                                false, &m_opts);
        if (resp.status >= 300 && resp.status < 400 && !location.empty())
            return CurlRequest(m_logTag, "GET", location, {}, {}, 60L, false, nullptr,
                               /*followRedirects=*/true, &m_opts);
        return resp;
    }

    const char* m_logTag;

private:
    // host+path helpers use https unless plaintext HTTP was explicitly enabled.
    std::string Scheme() const {
        return m_opts.allowInsecureHttp ? "http://" : "https://";
    }
    TransportOptions m_opts;
};

std::unique_ptr<IHttpTransport> CreateHttpTransport(const char* logTag) {
    return std::make_unique<DlopenCurlTransport>(logTag);
}
