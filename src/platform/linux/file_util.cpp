#include "file_util.h"
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>

namespace FileUtil {

bool AtomicWriteBinary(const std::string& path, const void* data, size_t len) {
    std::string tmp = path + ".tmp";

    int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return false;

    const uint8_t* p = static_cast<const uint8_t*>(data);
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t written = write(fd, p, remaining);
        if (written < 0) {
            if (errno == EINTR) continue;
            close(fd); unlink(tmp.c_str()); return false;
        }
        p += written;
        remaining -= written;
    }

    if (fsync(fd) != 0) {
        close(fd);
        unlink(tmp.c_str());
        return false;
    }
    if (close(fd) != 0) {
        unlink(tmp.c_str());
        return false;
    }

    if (rename(tmp.c_str(), path.c_str()) != 0) {
        unlink(tmp.c_str());
        return false;
    }
    return true;
}

bool AtomicWriteText(const std::string& path, const std::string& content) {
    return AtomicWriteBinary(path, content.data(), content.size());
}

} // namespace FileUtil
