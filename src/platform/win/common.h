#pragma once
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include <mutex>
#include <filesystem>
#include <fstream>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

// Note: kPathSep and kPathSepStr are now provided via Platform() in file_util.h
