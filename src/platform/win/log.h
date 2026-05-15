#pragma once
#include "common.h"

namespace Log {
    void Init(const char* path);
    void Shutdown();
    void Write(const char* fmt, ...);
}

#define LOG(fmt, ...) Log::Write(fmt, ##__VA_ARGS__)
