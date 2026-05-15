#include "log.h"
#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <ctime>
#include <mutex>
#include <sys/stat.h>

static FILE* g_logFile = nullptr;
static std::mutex g_logMutex;

void Log::Init()
{
    const char* home = getenv("HOME");
    if (!home) home = "/tmp";

    char path[512];
    snprintf(path, sizeof(path), "%s/.config/CloudRedirect/cloud_redirect.log", home);

    // Ensure directory exists
    char dir[512];
    snprintf(dir, sizeof(dir), "%s/.config", home);
    mkdir(dir, 0755);
    snprintf(dir, sizeof(dir), "%s/.config/CloudRedirect", home);
    mkdir(dir, 0755);

    g_logFile = fopen(path, "a");
    if (g_logFile) {
        fprintf(g_logFile, "\n--------------------------------------------------------------------------------\n");
        fflush(g_logFile);
        Info("=== CloudRedirect Linux started ===");
    }
}

void Log::Init(const char* /* path */)
{
    // Windows compat - ignore path, use standard location
    Init();
}

void Log::Shutdown()
{
    std::lock_guard<std::mutex> lock(g_logMutex);
    if (g_logFile) {
        fclose(g_logFile);
        g_logFile = nullptr;
    }
}

static void LogWrite(const char* level, const char* fmt, va_list args)
{
    std::lock_guard<std::mutex> lock(g_logMutex);

    time_t now = time(nullptr);
    struct tm tm;
    localtime_r(&now, &tm);

    char timeBuf[32];
    strftime(timeBuf, sizeof(timeBuf), "%H:%M:%S", &tm);

    FILE* out = g_logFile ? g_logFile : stderr;
    fprintf(out, "[%s][%s] ", timeBuf, level);
    vfprintf(out, fmt, args);
    fprintf(out, "\n");
    fflush(out);
}

void Log::Write(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    LogWrite("INFO", fmt, args);
    va_end(args);
}

void Log::Info(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    LogWrite("INFO", fmt, args);
    va_end(args);
}

void Log::Warn(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    LogWrite("WARN", fmt, args);
    va_end(args);
}

void Log::Error(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    LogWrite("ERR ", fmt, args);
    va_end(args);
}

void Log::Debug(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    LogWrite("DBG ", fmt, args);
    va_end(args);
}
