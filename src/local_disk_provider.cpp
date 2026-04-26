#include "local_disk_provider.h"
#include "file_util.h"
#include "log.h"
#include <filesystem>
#include <fstream>

bool LocalDiskProvider::Init(const std::string& rootPath) {
    // UTF-8; every fs call routes through FileUtil::Utf8ToPath.
    m_root = rootPath;
    if (!m_root.empty() && m_root.back() != '\\' && m_root.back() != '/')
        m_root += '\\';
    std::error_code ec;
    std::filesystem::create_directories(FileUtil::Utf8ToPath(m_root), ec);
    if (ec) {
        LOG("[LocalDiskProvider] Failed to create root %s: %s", m_root.c_str(), ec.message().c_str());
        return false;
    }
    LOG("[LocalDiskProvider] Initialized at: %s", m_root.c_str());
    return true;
}

std::string LocalDiskProvider::ToFullPath(const std::string& relPath) const {
    std::string full = m_root + relPath;
    for (auto& c : full) {
        if (c == '/') c = '\\';
    }
    // IsPathWithin canonicalizes both sides; one call covers traversal and
    // symlink-escape.
    if (!FileUtil::IsPathWithin(m_root, full)) {
        LOG("[LocalDiskProvider] BLOCKED path traversal: %s (root=%s)",
            relPath.c_str(), m_root.c_str());
        return {};
    }
    std::error_code ec;
    auto canonical = std::filesystem::weakly_canonical(FileUtil::Utf8ToPath(full), ec);
    if (ec) return {};
    return FileUtil::PathToUtf8(canonical);
}

bool LocalDiskProvider::Upload(const std::string& path,
                               const uint8_t* data, size_t len) {
    std::string full = ToFullPath(path);
    if (full.empty()) return false;
    auto parent = FileUtil::Utf8ToPath(full).parent_path();
    std::error_code ec;
    std::filesystem::create_directories(parent, ec);
    if (ec) {
        LOG("[LocalDiskProvider] Failed to create dirs for %s: %s", full.c_str(), ec.message().c_str());
        return false;
    }
    if (!FileUtil::AtomicWriteBinary(full, data, len)) {
        LOG("[LocalDiskProvider] Upload: atomic write failed %s (%zu bytes)", full.c_str(), len);
        return false;
    }
    return true;
}

bool LocalDiskProvider::Download(const std::string& path,
                                 std::vector<uint8_t>& outData) {
    std::string full = ToFullPath(path);
    if (full.empty()) return false;
    std::ifstream f(FileUtil::Utf8ToPath(full), std::ios::binary);
    if (!f) return false;
    outData.assign(std::istreambuf_iterator<char>(f),
                   std::istreambuf_iterator<char>());
    return true;
}

bool LocalDiskProvider::Remove(const std::string& path) {
    std::string full = ToFullPath(path);
    if (full.empty()) return false;
    std::error_code ec;
    std::filesystem::remove(FileUtil::Utf8ToPath(full), ec);
    // success if removed or never existed
    return !ec;
}

bool LocalDiskProvider::Exists(const std::string& path) {
    return CheckExists(path) == ExistsStatus::Exists;
}

ICloudProvider::ExistsStatus LocalDiskProvider::CheckExists(const std::string& path) {
    std::string full = ToFullPath(path);
    if (full.empty()) return ExistsStatus::Error;
    std::error_code ec;
    auto fsPath = FileUtil::Utf8ToPath(full);
    bool exists = std::filesystem::exists(fsPath, ec);
    if (ec) return ExistsStatus::Error;
    if (!exists) return ExistsStatus::Missing;
    bool regular = std::filesystem::is_regular_file(fsPath, ec);
    if (ec) return ExistsStatus::Error;
    return regular ? ExistsStatus::Exists : ExistsStatus::Missing;
}

std::vector<ICloudProvider::FileInfo> LocalDiskProvider::List(const std::string& prefix) {
    std::vector<FileInfo> result;
    ListChecked(prefix, result);
    return result;
}

bool LocalDiskProvider::ListChecked(const std::string& prefix, std::vector<FileInfo>& result,
                                    bool* outComplete) {
    result.clear();
    // Pessimistic default: only the verified-complete success path sets true.
    if (outComplete) *outComplete = false;
    std::string dir = ToFullPath(prefix);
    if (dir.empty()) return false;
    std::error_code ec;
    auto dirPath = FileUtil::Utf8ToPath(dir);
    bool exists = std::filesystem::exists(dirPath, ec);
    if (ec) return false;
    if (!exists) { if (outComplete) *outComplete = true; return true; }
    bool isDir = std::filesystem::is_directory(dirPath, ec);
    if (ec) return false;
    if (!isDir) { if (outComplete) *outComplete = true; return true; }

    // Capture both clocks once to avoid per-file jitter.
    auto fileClockNow = std::filesystem::file_time_type::clock::now();
    auto sysClockNow = std::chrono::system_clock::now();

    // No skip_permission_denied: an unreadable subtree must mark the listing
    // unverified, not silently disappear from it.
    std::filesystem::recursive_directory_iterator it(dirPath, ec);
    std::filesystem::recursive_directory_iterator end;
    // Per-entry stat failures don't fail the whole listing but mark it
    // incomplete so destructive prunes are suppressed.
    bool sawSkippedEntries = false;
    for (; !ec && it != end; it.increment(ec)) {
        const auto& entry = *it;
        std::error_code ec2;
        bool isFile = entry.is_regular_file(ec2);
        if (ec2) { sawSkippedEntries = true; continue; }
        if (!isFile) continue;

        std::string rel = FileUtil::PathToUtf8(
            std::filesystem::relative(entry.path(), FileUtil::Utf8ToPath(m_root), ec2));
        if (ec2) { sawSkippedEntries = true; continue; }
        // Forward slashes per ICloudProvider convention.
        for (auto& c : rel) {
            if (c == '\\') c = '/';
        }

        FileInfo fi;
        fi.path = rel;
        fi.size = entry.file_size(ec2);
        if (ec2) { sawSkippedEntries = true; continue; }

        auto ftime = std::filesystem::last_write_time(entry.path(), ec2);
        if (ec2) { sawSkippedEntries = true; continue; }
        auto sctp = std::chrono::time_point_cast<std::chrono::seconds>(
            ftime - fileClockNow + sysClockNow);
        fi.modifiedTime = (uint64_t)sctp.time_since_epoch().count();

        result.push_back(std::move(fi));
    }
    bool ok = !ec;
    if (ok && outComplete) *outComplete = !sawSkippedEntries;
    return ok;
}
