#pragma once
// Linux logging - matches Windows log.h API surface

#include "common.h"

namespace Log {
    void Init();
    void Init(const char* path);  // Windows compat - path ignored on Linux
    void Shutdown();
    void Write(const char* fmt, ...);
    
    // Additional logging levels (Linux-specific, also available)
    void Info(const char* fmt, ...);
    void Warn(const char* fmt, ...);
    void Error(const char* fmt, ...);
    void Debug(const char* fmt, ...);
}

#define LOG(fmt, ...) Log::Write(fmt, ##__VA_ARGS__)
