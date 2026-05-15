#pragma once
// Platform abstraction for file I/O and path encoding.

#include <string>
#include <filesystem>
#include <cstdint>
#include <vector>

struct IPlatform {
    virtual ~IPlatform() = default;
    
    // Path encoding: UTF-8 string <-> std::filesystem::path
    // On Windows, paths are wide (UTF-16); on Linux, paths are narrow (UTF-8).
    virtual std::filesystem::path Utf8ToPath(const std::string& utf8) = 0;
    virtual std::string PathToUtf8(const std::filesystem::path& p) = 0;
    
    // Wide string conversion (Windows-specific, identity on Linux)
    virtual std::string WideToUtf8(const wchar_t* w) = 0;
    virtual std::string WideToUtf8(const wchar_t* w, size_t len) = 0;
    
    // Atomic file write: write to .tmp, sync, rename over target.
    // Returns true on success.
    virtual bool AtomicWriteBinary(const std::string& path, const void* data, size_t len) = 0;
    virtual bool AtomicWriteText(const std::string& path, const std::string& content) = 0;
    
    // Path containment check: returns true if fullPath is under root.
    // Case-insensitive on Windows, case-sensitive on Linux.
    virtual bool IsPathWithin(const std::string& root, const std::string& fullPath) = 0;
    
    // Remove empty dirs from startDir up to stopAt.
    virtual void CleanupEmptyDirsUpTo(const std::string& startDir, const std::string& stopAt) = 0;
    
    // Check if path is a reparse point that redirects elsewhere (junctions, symlinks).
    // Always returns false on Linux.
    virtual bool IsPathRedirectingReparsePoint(const std::string& path) = 0;
    
    // Platform path separator: '\\' on Windows, '/' on Linux
    virtual char PathSeparator() const = 0;
    virtual const char* PathSeparatorStr() const = 0;
    
    // Normalize path separators: replace '/' with '\\' on Windows, no-op on Linux.
    virtual std::string NormalizePath(const std::string& path) const = 0;
    
    // SHA1 hash: returns 20-byte hash of input data.
    virtual std::vector<uint8_t> SHA1(const void* data, size_t len) = 0;
};

// Global platform instance - swappable for tests.
// Returns the real platform adapter by default.
IPlatform& Platform();
