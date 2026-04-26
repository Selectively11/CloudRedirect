#include "log.h"
#include "file_util.h"
#include <cstdarg>
#include <ctime>
#include <vector>

namespace Log {

static FILE* g_file = nullptr;
static std::mutex g_mutex;
static std::string g_logPath;

static constexpr long MAX_LOG_SIZE = 10 * 1024 * 1024;

// Records up to STACK_BUF bytes go through a stack buffer with no heap
// allocation; longer records (rare -- a stack trace dump or a serialized
// blob list) fall through to a one-shot heap allocation. Either way the
// finished record is emitted with a single fwrite() under the mutex so
// concurrent writers can never interleave fragments of each other's lines.
static constexpr size_t STACK_BUF = 1024;

// Open mode L"ab": append, binary. Binary is critical -- text mode causes the
// CRT to translate '\n' to "\r\n" on every write, which (a) silently corrupts
// any UTF-8 byte sequence that happens to contain 0x0A inside a multi-byte
// codepoint when interleaved with format-buffer reuse, and (b) makes our
// "single fwrite per record" guarantee meaningless because the CRT splits
// the buffer at every '\n' for the translation. We embed our own '\r\n' (or
// '\n' -- readers handle both) and bypass the translation entirely.
static FILE* OpenLog(const std::string& utf8Path) {
    if (utf8Path.empty()) return nullptr;
    auto wPath = FileUtil::Utf8ToPath(utf8Path);
    if (wPath.empty()) return nullptr;
    // path::c_str() returns wchar_t* on Windows -- exactly what _wfopen wants.
    return _wfopen(wPath.c_str(), L"ab");
}

// Single-fwrite record emission. Caller must hold g_mutex.
// On any error path we silently drop the record -- logging must never throw
// or block, especially on the cloud RPC hot path.
static void WriteRecord(const char* data, size_t len) {
    if (!g_file || !data || len == 0) return;
    fwrite(data, 1, len, g_file);
    fflush(g_file);
}

// Check file size and rotate if needed (caller must hold g_mutex)
static void RotateIfNeeded() {
    if (!g_file) return;
    long pos = ftell(g_file);
    if (pos < 0 || pos < MAX_LOG_SIZE) return;

    fclose(g_file);

    // Rename current log to .old (overwrite any previous .old). Both paths
    // route through FileUtil::Utf8ToPath so non-ASCII Steam install paths
    // (e.g. "C:\Users\Владимир\Steam\cloud_redirect.log") rotate correctly.
    auto logPathFs = FileUtil::Utf8ToPath(g_logPath);
    auto oldPathFs = FileUtil::Utf8ToPath(g_logPath + ".old");
    if (!oldPathFs.empty()) _wremove(oldPathFs.c_str());
    if (!logPathFs.empty() && !oldPathFs.empty())
        _wrename(logPathFs.c_str(), oldPathFs.c_str());

    g_file = OpenLog(g_logPath);
    if (g_file) {
        const char banner[] = "=== Log rotated (previous log saved as .old) ===\n";
        WriteRecord(banner, sizeof(banner) - 1);
    }
}

void Init(const char* path) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_logPath = path ? path : "";
    g_file = OpenLog(g_logPath);
    if (g_file) {
        time_t t = time(nullptr);
        tm lt;
        localtime_s(&lt, &t);
        char buf[128];
        int n = snprintf(buf, sizeof(buf),
                         "\n=== CloudRedirect loaded at %04d-%02d-%02d %02d:%02d:%02d ===\n",
                         lt.tm_year + 1900, lt.tm_mon + 1, lt.tm_mday,
                         lt.tm_hour, lt.tm_min, lt.tm_sec);
        if (n > 0) WriteRecord(buf, (size_t)n);
    }
}

void Shutdown() {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_file) {
        const char banner[] = "=== CloudRedirect unloaded ===\n";
        WriteRecord(banner, sizeof(banner) - 1);
        fclose(g_file);
        g_file = nullptr;
    }
}

void Write(const char* fmt, ...) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_file) return;

    RotateIfNeeded();
    if (!g_file) return; // rotation may have failed

    // Build the entire record (timestamp + caller's formatted line + '\n')
    // into a single buffer, then emit with one fwrite. Previously we issued
    // four separate fprintf calls -- each one a distinct write to the FILE*
    // buffer -- so two threads logging concurrently could interleave their
    // fragments inside the kernel buffer. The mutex above prevents that
    // here, but the single-write design also matches what a future async /
    // lock-free log queue would require, and removes the dependency on
    // _IOLBF buffering semantics.
    char stack[STACK_BUF];
    char* buf = stack;
    size_t cap = sizeof(stack);
    std::vector<char> heap;

    time_t t = time(nullptr);
    tm lt;
    localtime_s(&lt, &t);
    int prefix = snprintf(buf, cap, "[%02d:%02d:%02d] ",
                          lt.tm_hour, lt.tm_min, lt.tm_sec);
    if (prefix < 0) return;
    if ((size_t)prefix >= cap) {
        // Pathological: timestamp didn't fit. Bail rather than recurse.
        return;
    }

    va_list args;
    va_start(args, fmt);
    va_list argsCopy;
    va_copy(argsCopy, args);
    int bodyLen = vsnprintf(buf + prefix, cap - prefix, fmt, args);
    va_end(args);

    if (bodyLen < 0) {
        va_end(argsCopy);
        return;
    }

    size_t need = (size_t)prefix + (size_t)bodyLen + 1; // +1 for '\n'
    if (need > cap) {
        // Caller's formatted line exceeded the stack buffer -- promote to
        // heap and re-format. Re-using the va_list copy avoids the second
        // call into varargs the caller already consumed.
        heap.resize(need + 1);
        buf = heap.data();
        cap = heap.size();
        memcpy(buf, stack, (size_t)prefix);
        bodyLen = vsnprintf(buf + prefix, cap - prefix, fmt, argsCopy);
        if (bodyLen < 0) {
            va_end(argsCopy);
            return;
        }
    }
    va_end(argsCopy);

    size_t total = (size_t)prefix + (size_t)bodyLen;
    buf[total++] = '\n';
    WriteRecord(buf, total);
}

} // namespace Log
