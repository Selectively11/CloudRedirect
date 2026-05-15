
#include "cloud_provider_base.h"
#include "log.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

static constexpr size_t kMaxResponseSize = 64 * 1024 * 1024; // 64 MiB
static const char* kStatusMarker = "__CR_HTTP_STATUS__:";

static const char* FindCurlBinary() {
    static const char* paths[] = {"/usr/bin/curl", "/bin/curl", "/usr/local/bin/curl"};
    for (const char* path : paths) {
        if (access(path, X_OK) == 0)
            return path;
    }
    return nullptr;
}

static std::string CurlQuote(const std::string& value) {
    std::string out = "\"";
    for (char c : value) {
        if (c == '\n') {
            out += "\\n";
            continue;
        }
        if (c == '\r') {
            out += "\\r";
            continue;
        }
        if (c == '\\' || c == '"')
            out.push_back('\\');
        out.push_back(c);
    }
    out.push_back('"');
    return out;
}

static bool WriteAllFd(int fd, const char* data, size_t len) {
    while (len > 0) {
        ssize_t n = write(fd, data, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        data += n;
        len -= (size_t)n;
    }
    return true;
}

static bool WriteTempFile(const std::string& content, std::string& path) {
    char tmpl[] = "/tmp/cloudredirect-curl-XXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0)
        return false;
    path = tmpl;
    bool ok = WriteAllFd(fd, content.data(), content.size());
    if (close(fd) != 0)
        ok = false;
    if (!ok) {
        unlink(path.c_str());
        path.clear();
    }
    return ok;
}

static bool ExtractStatus(HttpUtil::HttpResp& resp) {
    size_t marker = resp.body.rfind(kStatusMarker);
    if (marker == std::string::npos)
        return false;

    char* end = nullptr;
    long status = strtol(resp.body.c_str() + marker + strlen(kStatusMarker), &end, 10);
    if (status < 0 || status > 599)
        return false;

    size_t eraseFrom = marker;
    if (eraseFrom > 0 && resp.body[eraseFrom - 1] == '\n')
        --eraseFrom;
    resp.body.erase(eraseFrom);
    resp.status = (int)status;
    return true;
}

static bool StartsWithHttpStatus(const std::string& s, size_t pos) {
    return s.compare(pos, 5, "HTTP/") == 0;
}

static void StripIncludedHeaders(HttpUtil::HttpResp& resp, std::string* location) {
    size_t pos = 0;
    while (StartsWithHttpStatus(resp.body, pos)) {
        size_t end = resp.body.find("\r\n\r\n", pos);
        size_t sepLen = 4;
        if (end == std::string::npos) {
            end = resp.body.find("\n\n", pos);
            sepLen = 2;
        }
        if (end == std::string::npos)
            return;

        if (location) {
            size_t line = pos;
            while (line < end) {
                size_t next = resp.body.find('\n', line);
                if (next == std::string::npos || next > end)
                    next = end;
                std::string header = resp.body.substr(line, next - line);
                if (!header.empty() && header.back() == '\r')
                    header.pop_back();
                if (header.size() > 9 &&
                    (header.compare(0, 9, "Location:") == 0 || header.compare(0, 9, "location:") == 0)) {
                    *location = header.substr(9);
                    while (!location->empty() && (location->front() == ' ' || location->front() == '\t'))
                        location->erase(location->begin());
                    while (!location->empty() && (location->back() == ' ' || location->back() == '\t'))
                        location->pop_back();
                }
                line = next + 1;
            }
        }

        pos = end + sepLen;
    }
    resp.body.erase(0, pos);
}

class ExternalCurlTransport : public IHttpTransport {
public:
    explicit ExternalCurlTransport(const char* logTag) : m_logTag(logTag) {}

    bool Init() override {
        m_curlPath = FindCurlBinary();
        if (!m_curlPath) {
            LOG("[CurlTransport] ERROR: curl binary not found in /usr/bin, /bin, or /usr/local/bin");
            return false;
        }
        m_ready = true;
        LOG("[CurlTransport] using external curl process at %s", m_curlPath);
        return true;
    }

    void Shutdown() override {
        m_ready = false;
    }

    bool IsReady() const override { return m_ready; }

    HttpUtil::HttpResp Request(const char* method, const char* host,
                               const std::string& path,
                               const std::string& body,
                               const std::vector<std::string>& hdrs) override {
        std::string url = std::string("https://") + host + path;
        return RunCurl(method, url, body, hdrs, 30L, false, nullptr);
    }

    HttpUtil::HttpResp RequestUrl(const char* method, const std::string& fullUrl,
                                  const std::string& body,
                                  const std::vector<std::string>& hdrs) override {
        return RunCurl(method, fullUrl, body, hdrs, 60L, false, nullptr);
    }

    HttpUtil::HttpResp AuthenticatedGetWithRedirect(const std::string& host,
                                                     const std::string& path,
                                                     const std::string& authHeader) override {
        std::string location;
        std::string url = std::string("https://") + host + path;
        auto resp = RunCurl("GET", url, {}, {authHeader}, 30L, true, &location);
        if (resp.status == 302 && !location.empty())
            return RequestUrl("GET", location, {}, {});
        return resp;
    }

private:
    HttpUtil::HttpResp RunCurl(const char* method, const std::string& url,
                               const std::string& body,
                               const std::vector<std::string>& hdrs,
                               long timeoutSeconds,
                               bool includeHeaders,
                               std::string* location) {
        HttpUtil::HttpResp resp;
        if (url.substr(0, 8) != "https://") {
            LOG("%s BLOCKED non-HTTPS request: %s", m_logTag, url.c_str());
            return resp;
        }

        std::string bodyPath;
        if (!body.empty() && !WriteTempFile(body, bodyPath)) {
            LOG("%s curl body temp file failed", m_logTag);
            return resp;
        }

        std::string config;
        config += "silent\n";
        config += "show-error\n";
        config += "connect-timeout = 5\n";
        config += "max-time = " + std::to_string(timeoutSeconds) + "\n";
        config += "user-agent = " + CurlQuote("CloudRedirect/1.0") + "\n";
        config += "request = " + CurlQuote(method) + "\n";
        config += "url = " + CurlQuote(url) + "\n";
        config += "output = -\n";
        config += "write-out = " + CurlQuote(std::string("\n") + kStatusMarker + "%{http_code}\n") + "\n";
        if (includeHeaders)
            config += "include\n";
        for (const auto& h : hdrs)
            config += "header = " + CurlQuote(h) + "\n";
        if (!bodyPath.empty())
            config += "data-binary = " + CurlQuote("@" + bodyPath) + "\n";

        std::string configPath;
        if (!WriteTempFile(config, configPath)) {
            if (!bodyPath.empty())
                unlink(bodyPath.c_str());
            LOG("%s curl config temp file failed", m_logTag);
            return resp;
        }

        int outPipe[2];
        int errPipe[2];
        if (pipe(outPipe) != 0) {
            CleanupTempFiles(configPath, bodyPath);
            return resp;
        }
        if (pipe(errPipe) != 0) {
            close(outPipe[0]);
            close(outPipe[1]);
            CleanupTempFiles(configPath, bodyPath);
            return resp;
        }

        pid_t pid = fork();
        if (pid == 0) {
            dup2(outPipe[1], STDOUT_FILENO);
            dup2(errPipe[1], STDERR_FILENO);
            close(outPipe[0]);
            close(outPipe[1]);
            close(errPipe[0]);
            close(errPipe[1]);
            
            // Unset Steam runtime LD_LIBRARY_PATH so curl uses system libcurl
            unsetenv("LD_LIBRARY_PATH");
            unsetenv("LD_PRELOAD");
            
            execl(m_curlPath, "curl", "--config", configPath.c_str(), (char*)nullptr);
            const char* msg = "execl failed\n";
            write(STDERR_FILENO, msg, strlen(msg));
            _exit(127);
        }

        close(outPipe[1]);
        close(errPipe[1]);
        if (pid < 0) {
            close(outPipe[0]);
            close(errPipe[0]);
            CleanupTempFiles(configPath, bodyPath);
            return resp;
        }

        std::string stderrOutput;
        char buf[8192];
        for (;;) {
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(outPipe[0], &readfds);
            FD_SET(errPipe[0], &readfds);
            int maxfd = (outPipe[0] > errPipe[0] ? outPipe[0] : errPipe[0]) + 1;

            int ret = select(maxfd, &readfds, nullptr, nullptr, nullptr);
            if (ret < 0) {
                if (errno == EINTR)
                    continue;
                break;
            }

            if (FD_ISSET(outPipe[0], &readfds)) {
                ssize_t n = read(outPipe[0], buf, sizeof(buf));
                if (n < 0) {
                    if (errno != EINTR)
                        break;
                } else if (n == 0) {
                    close(outPipe[0]);
                    outPipe[0] = -1;
                } else {
                    if (resp.body.size() + (size_t)n > kMaxResponseSize) {
                        LOG("%s curl response too large", m_logTag);
                        break;
                    }
                    resp.body.append(buf, (size_t)n);
                }
            }

            if (FD_ISSET(errPipe[0], &readfds)) {
                ssize_t n = read(errPipe[0], buf, sizeof(buf));
                if (n < 0) {
                    if (errno != EINTR)
                        break;
                } else if (n == 0) {
                    close(errPipe[0]);
                    errPipe[0] = -1;
                } else {
                    if (stderrOutput.size() + (size_t)n < 4096)
                        stderrOutput.append(buf, (size_t)n);
                }
            }

            if (outPipe[0] == -1 && errPipe[0] == -1)
                break;
        }

        if (outPipe[0] != -1)
            close(outPipe[0]);
        if (errPipe[0] != -1)
            close(errPipe[0]);

        int status = 0;
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        CleanupTempFiles(configPath, bodyPath);

        if (WIFEXITED(status)) {
            int exitCode = WEXITSTATUS(status);
            if (exitCode == 127) {
                LOG("%s curl exec failed: %s", m_logTag, 
                    stderrOutput.empty() ? "not found or not executable" : stderrOutput.c_str());
                resp = {};
                return resp;
            }
            if (exitCode != 0 && !stderrOutput.empty()) {
                LOG("%s curl exited %d: %s", m_logTag, exitCode, stderrOutput.c_str());
            }
        } else if (WIFSIGNALED(status)) {
            LOG("%s curl killed by signal %d", m_logTag, WTERMSIG(status));
        }

        if (!ExtractStatus(resp)) {
            LOG("%s external curl failed (%s %s)%s%s", m_logTag, method, url.c_str(),
                stderrOutput.empty() ? "" : ": ", stderrOutput.c_str());
            resp = {};
            return resp;
        }
        if (includeHeaders)
            StripIncludedHeaders(resp, location);
        return resp;
    }

    void CleanupTempFiles(const std::string& configPath, const std::string& bodyPath) {
        if (!configPath.empty())
            unlink(configPath.c_str());
        if (!bodyPath.empty())
            unlink(bodyPath.c_str());
    }

    const char* m_logTag;
    const char* m_curlPath = nullptr;
    bool m_ready = false;
};

std::unique_ptr<IHttpTransport> CreateHttpTransport(const char* logTag) {
    return std::make_unique<ExternalCurlTransport>(logTag);
}
