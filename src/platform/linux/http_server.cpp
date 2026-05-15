#include "http_server.h"
#include "file_util.h"
#include "cloud_storage.h"
#include "log.h"
#include "miniz.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <cerrno>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>
#include <set>
#include <algorithm>
#include <memory>
#include <filesystem>
#include <fstream>
#include <cstring>
#include <sstream>
#include <stdexcept>

static std::string g_blobRoot;
static uint32_t g_accountId = 0;
static uint16_t g_port = 0;
static int g_listenFd = -1;
static std::atomic<bool> g_running{false};
static std::atomic<int> g_activeConnections{0};
static std::atomic<uint64_t> g_maxUploadBytes{256ULL * 1024 * 1024};  // 256 MB default
static constexpr int MAX_CONCURRENT_CONNECTIONS = 64;
static std::thread g_serverThread;
struct ClientThread {
    std::thread thread;
    std::shared_ptr<std::atomic<bool>> done;
};
static std::vector<ClientThread> g_clientThreads;
static std::mutex g_clientMutex;
static std::set<int> g_clientFds;
static std::mutex g_clientFdMutex;

static void RegisterClientFd(int fd) {
    std::lock_guard<std::mutex> lock(g_clientFdMutex);
    g_clientFds.insert(fd);
}

static void UnregisterClientFd(int fd) {
    std::lock_guard<std::mutex> lock(g_clientFdMutex);
    g_clientFds.erase(fd);
}

static std::string BlobPath(uint32_t accountId, uint32_t appId, const std::string& filename) {
    return g_blobRoot + "/" + std::to_string(accountId) + "/" +
           std::to_string(appId) + "/" + filename;
}

static std::string UrlDecode(const std::string& encoded) {
    std::string result;
    result.reserve(encoded.size());
    for (size_t i = 0; i < encoded.size(); ++i) {
        if (encoded[i] == '%' && i + 2 < encoded.size()) {
            int hi = 0, lo = 0;
            char c1 = encoded[i + 1], c2 = encoded[i + 2];
            if (c1 >= '0' && c1 <= '9') hi = c1 - '0';
            else if (c1 >= 'A' && c1 <= 'F') hi = c1 - 'A' + 10;
            else if (c1 >= 'a' && c1 <= 'f') hi = c1 - 'a' + 10;
            else { result += encoded[i]; continue; }
            if (c2 >= '0' && c2 <= '9') lo = c2 - '0';
            else if (c2 >= 'A' && c2 <= 'F') lo = c2 - 'A' + 10;
            else if (c2 >= 'a' && c2 <= 'f') lo = c2 - 'a' + 10;
            else { result += encoded[i]; continue; }
            result += static_cast<char>((hi << 4) | lo);
            i += 2;
        } else {
            result += encoded[i];
        }
    }
    return result;
}

// Decompress Steam's cloud-compression ZIP. Returns false (and leaves out untouched) on non-ZIP or failure.
static bool TryDecompressZip(const std::vector<uint8_t>& data, std::vector<uint8_t>& out) {
    if (data.size() < 4) return false;
    if (data[0] != 0x50 || data[1] != 0x4B || data[2] != 0x03 || data[3] != 0x04)
        return false;

    mz_zip_archive zip{};
    if (!mz_zip_reader_init_mem(&zip, data.data(), data.size(), 0)) {
        LOG("[HttpServer] ZIP init failed: %s", mz_zip_get_error_string(mz_zip_get_last_error(&zip)));
        return false;
    }

    // Steam cloud ZIP is single-entry, inner name "z"; anything else is a game save that's natively ZIP.
    if (mz_zip_reader_get_num_files(&zip) != 1) {
        mz_zip_reader_end(&zip);
        return false;
    }
    mz_zip_archive_file_stat fstat;
    if (!mz_zip_reader_file_stat(&zip, 0, &fstat) ||
        strcmp(fstat.m_filename, "z") != 0) {
        mz_zip_reader_end(&zip);
        return false;
    }

    // Reject if uncompressed size exceeds 512 MB or would overflow size_t
    if (fstat.m_uncomp_size > 512ULL * 1024 * 1024 || fstat.m_uncomp_size > SIZE_MAX) {
        LOG("[HttpServer] ZIP rejected: declared size %llu", (unsigned long long)fstat.m_uncomp_size);
        mz_zip_reader_end(&zip);
        return false;
    }

    size_t uncompSize = 0;
    void* p = mz_zip_reader_extract_to_heap(&zip, 0, &uncompSize, 0);
    mz_zip_reader_end(&zip);

    if (!p) {
        LOG("[HttpServer] ZIP extract failed");
        return false;
    }

    out.assign(static_cast<uint8_t*>(p), static_cast<uint8_t*>(p) + uncompSize);
    mz_free(p);
    return true;
}

// Verify the connecting client is our own process via /proc/net/tcp inode lookup.
static bool IsConnectionFromSteam(int clientFd) {
    sockaddr_in peer{};
    socklen_t peerLen = sizeof(peer);
    if (getpeername(clientFd, (sockaddr*)&peer, &peerLen) != 0) return false;
    
    uint16_t peerPort = ntohs(peer.sin_port);
    uint32_t peerAddr = ntohl(peer.sin_addr.s_addr);
    
    sockaddr_in local{};
    socklen_t localLen = sizeof(local);
    if (getsockname(clientFd, (sockaddr*)&local, &localLen) != 0) return false;
    
    uint16_t localPort = ntohs(local.sin_port);
    uint32_t localAddr = ntohl(local.sin_addr.s_addr);
    
    // /proc/net/tcp format: sl local_address:port rem_address:port st ... inode
    // Addresses are network-byte-order hex.
    std::ifstream tcpFile("/proc/net/tcp");
    if (!tcpFile) return false;
    
    unsigned long socketInode = 0;
    std::string line;
    std::getline(tcpFile, line); // skip header
    
    while (std::getline(tcpFile, line)) {
        unsigned int localAddrHex, localPortHex, remAddrHex, remPortHex;
        unsigned long inode;
        int st;
        if (sscanf(line.c_str(), " %*d: %X:%X %X:%X %X %*X:%*X %*X:%*X %*X %*u %*u %lu",
                   &localAddrHex, &localPortHex, &remAddrHex, &remPortHex, &st, &inode) == 6) {
            // Match client's row: its local=peer, its remote=us, ESTABLISHED
            if (localAddrHex == htonl(peerAddr) && localPortHex == peerPort &&
                remAddrHex == htonl(localAddr) && remPortHex == localPort &&
                st == 1) {
                socketInode = inode;
                break;
            }
        }
    }
    tcpFile.close();
    
    if (socketInode == 0) {
        LOG("[HttpServer] PID check: socket inode not found for port %u", peerPort);
        return false;
    }
    
    // Find which PID owns this socket inode
    pid_t myPid = getpid();
    char inodeTarget[64];
    snprintf(inodeTarget, sizeof(inodeTarget), "socket:[%lu]", socketInode);
    
    DIR* procDir = opendir("/proc");
    if (!procDir) return false;
    
    pid_t ownerPid = 0;
    struct dirent* procEntry;
    while ((procEntry = readdir(procDir)) != nullptr) {
        char* endptr;
        long pid = strtol(procEntry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid <= 0) continue;
        
        char fdPath[64];
        snprintf(fdPath, sizeof(fdPath), "/proc/%ld/fd", pid);
        DIR* fdDir = opendir(fdPath);
        if (!fdDir) continue;
        
        struct dirent* fdEntry;
        while ((fdEntry = readdir(fdDir)) != nullptr) {
            char linkPath[128];
            char linkTarget[128];
            snprintf(linkPath, sizeof(linkPath), "/proc/%ld/fd/%s", pid, fdEntry->d_name);
            ssize_t len = readlink(linkPath, linkTarget, sizeof(linkTarget) - 1);
            if (len > 0) {
                linkTarget[len] = '\0';
                if (strcmp(linkTarget, inodeTarget) == 0) {
                    ownerPid = static_cast<pid_t>(pid);
                    break;
                }
            }
        }
        closedir(fdDir);
        if (ownerPid != 0) break;
    }
    closedir(procDir);
    
    if (ownerPid == 0) {
        LOG("[HttpServer] PID check: owner not found for inode %lu", socketInode);
        return false;
    }
    
    if (ownerPid != myPid) {
        LOG("[HttpServer] BLOCKED connection from PID %d (expected %d) on port %u",
            ownerPid, myPid, peerPort);
        return false;
    }
    
    return true;
}

static bool ParseRequestLine(const char* buf, size_t len, std::string& method, std::string& path) {
    std::string line(buf, std::min(len, (size_t)4096));
    auto endOfLine = line.find("\r\n");
    if (endOfLine != std::string::npos) line = line.substr(0, endOfLine);
    
    auto sp1 = line.find(' ');
    if (sp1 == std::string::npos) return false;
    method = line.substr(0, sp1);
    
    auto sp2 = line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) return false;
    path = line.substr(sp1 + 1, sp2 - sp1 - 1);
    
    return true;
}

static void HandleConnection(int clientFd) {
    char buf[8192];
    ssize_t totalRead = 0;
    
    while (totalRead < (ssize_t)sizeof(buf) - 1) {
        ssize_t n = recv(clientFd, buf + totalRead, sizeof(buf) - 1 - totalRead, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        totalRead += n;
        buf[totalRead] = '\0';
        if (strstr(buf, "\r\n\r\n")) break;
    }
    
    if (totalRead <= 0 || !strstr(buf, "\r\n\r\n")) {
        close(clientFd);
        return;
    }
    
    std::string method, path;
    if (!ParseRequestLine(buf, totalRead, method, path)) {
        const char* resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        send(clientFd, resp, strlen(resp), 0);
        close(clientFd);
        return;
    }
    
    LOG("[HttpServer] %s %s", method.c_str(), path.c_str());
    
    bool isDownload = (method == "GET" && path.rfind("/download/", 0) == 0);
    bool isUpload = (method == "PUT" && path.rfind("/upload/", 0) == 0);
    
    if (!isDownload && !isUpload) {
        const char* resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        send(clientFd, resp, strlen(resp), 0);
        close(clientFd);
        return;
    }
    
    // Parse: /{download|upload}/{accountId}/{appId}/{filename...}
    std::string remainder = path.substr(isDownload ? 10 : 8); // skip "/download/" or "/upload/"
    auto slash1 = remainder.find('/');
    if (slash1 == std::string::npos) {
        const char* resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        send(clientFd, resp, strlen(resp), 0);
        close(clientFd);
        return;
    }
    
    uint32_t accountId;
    try { accountId = std::stoul(remainder.substr(0, slash1)); }
    catch (...) {
        const char* resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        send(clientFd, resp, strlen(resp), 0);
        close(clientFd);
        return;
    }
    if (accountId == 0) {
        const char* resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        send(clientFd, resp, strlen(resp), 0);
        close(clientFd);
        return;
    }
    remainder = remainder.substr(slash1 + 1);
    
    auto slash2 = remainder.find('/');
    if (slash2 == std::string::npos) {
        const char* resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        send(clientFd, resp, strlen(resp), 0);
        close(clientFd);
        return;
    }
    
    uint32_t appId;
    try { appId = std::stoul(remainder.substr(0, slash2)); }
    catch (...) {
        const char* resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        send(clientFd, resp, strlen(resp), 0);
        close(clientFd);
        return;
    }
    std::string rawFilename = remainder.substr(slash2 + 1);
    std::string filename = UrlDecode(rawFilename);
    // Double-decode to catch double-encoded traversal attempts.
    // E.g., %252e%252e -> %2e%2e -> .. 
    // Single-encoded . is idempotent, so no false positives.
    std::string filename2 = UrlDecode(filename);
    
    // Strip query string if present (e.g., "file.txt?raw=1" -> "file.txt")
    auto qpos = filename.find('?');
    if (qpos != std::string::npos) {
        filename.resize(qpos);
    }
    
    if (filename.find("..") != std::string::npos ||
        filename.find('\0') != std::string::npos ||
        (!filename.empty() && filename[0] == '/') ||
        filename2.find("..") != std::string::npos ||
        filename2.find('\0') != std::string::npos ||
        (!filename2.empty() && filename2[0] == '/')) {
        LOG("[HttpServer] Path traversal attempt blocked: %s", filename.c_str());
        const char* resp = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        send(clientFd, resp, strlen(resp), 0);
        close(clientFd);
        return;
    }
    
    std::string filePath = BlobPath(accountId, appId, filename);
    
    // Defense-in-depth: canonical path containment check
    if (!FileUtil::IsPathWithin(g_blobRoot, filePath)) {
        LOG("[HttpServer] Path containment check failed: %s", filePath.c_str());
        const char* resp = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        send(clientFd, resp, strlen(resp), 0);
        close(clientFd);
        return;
    }
    
    // Handle upload (PUT)
    if (isUpload) {
        uint64_t contentLength = 0;
        bool hasContentLength = false;
        // Case-insensitive Content-Length search (headers only, exclude body)
        const char* bodySep = strstr(buf, "\r\n\r\n");
        size_t headerLen = bodySep ? (size_t)(bodySep - buf + 4) : totalRead;
        std::string headerStr(buf, headerLen);
        std::string headerLower = headerStr;
        for (auto& c : headerLower) c = (char)tolower((unsigned char)c);
        auto clPos = headerLower.find("\r\ncontent-length:");
        if (clPos == std::string::npos) clPos = headerLower.find("\ncontent-length:");
        if (clPos != std::string::npos) {
            hasContentLength = true;
            auto lineEnd = headerStr.find("\r\n", clPos);
            size_t prefixLen = (headerLower[clPos] == '\r' ? 17 : 16);
            size_t valueLen = (lineEnd != std::string::npos) ? (lineEnd - clPos - prefixLen) : std::string::npos;
            std::string clValue = headerStr.substr(clPos + prefixLen, valueLen);
            while (!clValue.empty() && (clValue[0] == ' ' || clValue[0] == '\t')) 
                clValue = clValue.substr(1);
            // Trim trailing whitespace too
            while (!clValue.empty() && (clValue.back() == ' ' || clValue.back() == '\t'))
                clValue.pop_back();
            try { contentLength = std::stoull(clValue); }
            catch (...) {
                LOG("[HttpServer] Invalid Content-Length header: %s", clValue.c_str());
                const char* resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
                send(clientFd, resp, strlen(resp), 0);
                close(clientFd);
                return;
            }
        }
        
        // Require Content-Length header for uploads
        if (!hasContentLength) {
            LOG("[HttpServer] PUT missing Content-Length header");
            const char* resp = "HTTP/1.1 411 Length Required\r\nContent-Length: 0\r\n\r\n";
            send(clientFd, resp, strlen(resp), 0);
            close(clientFd);
            return;
        }
        
        uint64_t maxUpload = g_maxUploadBytes.load(std::memory_order_relaxed);
        if (contentLength > maxUpload) {
            LOG("[HttpServer] Upload rejected: size %llu exceeds limit %llu",
                (unsigned long long)contentLength, (unsigned long long)maxUpload);
            const char* resp = "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n";
            send(clientFd, resp, strlen(resp), 0);
            close(clientFd);
            return;
        }
        
        // On 32-bit, SIZE_MAX is 4GB; clamp to prevent vector overflow
        if (contentLength > SIZE_MAX) {
            LOG("[HttpServer] Upload rejected: size exceeds addressable memory");
            const char* resp = "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n";
            send(clientFd, resp, strlen(resp), 0);
            close(clientFd);
            return;
        }
        
        const char* bodyStart = strstr(buf, "\r\n\r\n");
        size_t bodyOffset = bodyStart ? (bodyStart - buf + 4) : totalRead;
        size_t alreadyRead = totalRead - bodyOffset;
        
        // Buffer body in memory for ZIP decompression
        std::vector<uint8_t> bodyData;
        bodyData.reserve(contentLength);
        
        if (alreadyRead > 0 && bodyStart) {
            size_t toCopy = std::min(alreadyRead, (size_t)contentLength);
            bodyData.insert(bodyData.end(), 
                reinterpret_cast<const uint8_t*>(bodyStart + 4),
                reinterpret_cast<const uint8_t*>(bodyStart + 4 + toCopy));
        }
        
        char recvBuf[65536];
        while (bodyData.size() < contentLength) {
            ssize_t n = recv(clientFd, recvBuf, std::min(sizeof(recvBuf), (size_t)(contentLength - bodyData.size())), 0);
            if (n < 0) {
                if (errno == EINTR) continue;
                LOG("[HttpServer] Upload recv failed at %zu/%llu bytes", bodyData.size(), (unsigned long long)contentLength);
                close(clientFd);
                return;
            }
            if (n == 0) {
                LOG("[HttpServer] Upload connection closed at %zu/%llu bytes", bodyData.size(), (unsigned long long)contentLength);
                close(clientFd);
                return;
            }
            bodyData.insert(bodyData.end(), recvBuf, recvBuf + n);
        }
        
        // Decompress Steam's ZIP wrapper (single entry named "z") if present
        std::vector<uint8_t> decompressed;
        if (TryDecompressZip(bodyData, decompressed)) {
            LOG("[HttpServer] PUT %s -> decompressed %zu -> %zu bytes",
                path.c_str(), bodyData.size(), decompressed.size());
            bodyData = std::move(decompressed);
        }
        
        auto parent = std::filesystem::path(filePath).parent_path();
        std::error_code ec;
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            LOG("[HttpServer] Failed to create directories: %s", ec.message().c_str());
            const char* resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
            send(clientFd, resp, strlen(resp), 0);
            close(clientFd);
            return;
        }
        
        if (!FileUtil::AtomicWriteBinary(filePath, bodyData.data(), bodyData.size())) {
            LOG("[HttpServer] PUT %s -> WRITE FAILED for %s", path.c_str(), filePath.c_str());
            const char* resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
            send(clientFd, resp, strlen(resp), 0);
            close(clientFd);
            return;
        }
        
        LOG("[HttpServer] PUT %s -> stored %zu bytes (app %u, file %s)",
            path.c_str(), bodyData.size(), appId, filename.c_str());
        const char* resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        send(clientFd, resp, strlen(resp), 0);
        close(clientFd);
        return;
    }
    
    // Download (GET) - use RetrieveBlob which fetches from cloud on cache miss
    bool found = false;
    std::vector<uint8_t> data = CloudStorage::RetrieveBlob(accountId, appId, filename, &found);
    
    if (!found) {
        LOG("[HttpServer] File not found (local or cloud): %s", filename.c_str());
        const char* resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        send(clientFd, resp, strlen(resp), 0);
        close(clientFd);
        return;
    }
    
    std::ostringstream headers;
    headers << "HTTP/1.1 200 OK\r\n"
            << "Content-Length: " << data.size() << "\r\n"
            << "Content-Type: application/octet-stream\r\n"
            << "\r\n";
    std::string headerStr = headers.str();
    send(clientFd, headerStr.c_str(), headerStr.size(), 0);
    
    size_t sent = 0;
    while (sent < data.size()) {
        size_t toSend = std::min(data.size() - sent, (size_t)65536);
        ssize_t n = send(clientFd, reinterpret_cast<const char*>(data.data() + sent), toSend, 0);
        if (n <= 0) {
            LOG("[HttpServer] Send failed at %zu/%zu bytes", sent, data.size());
            close(clientFd);
            return;
        }
        sent += n;
    }
    
    LOG("[HttpServer] Served %s (%zu bytes)", filename.c_str(), sent);
    close(clientFd);
}

namespace HttpServer {

bool Start(const std::string& blobRoot, uint32_t accountId) {
    g_blobRoot = blobRoot;
    g_accountId = accountId;

    g_listenFd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listenFd < 0) {
        LOG("[HttpServer] Failed to create socket");
        return false;
    }

    int opt = 1;
    setsockopt(g_listenFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0; // OS assigns port

    if (bind(g_listenFd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG("[HttpServer] Failed to bind");
        close(g_listenFd);
        g_listenFd = -1;
        return false;
    }

    socklen_t addrLen = sizeof(addr);
    getsockname(g_listenFd, (struct sockaddr*)&addr, &addrLen);
    g_port = ntohs(addr.sin_port);

    if (listen(g_listenFd, 16) < 0) {
        LOG("[HttpServer] Failed to listen");
        close(g_listenFd);
        g_listenFd = -1;
        return false;
    }

    g_running = true;
    g_serverThread = std::thread([]() {
        while (g_running) {
            struct sockaddr_in clientAddr{};
            socklen_t clientLen = sizeof(clientAddr);
            int clientFd = accept(g_listenFd, (struct sockaddr*)&clientAddr, &clientLen);
            if (clientFd < 0) {
                if (g_running) LOG("[HttpServer] accept() failed");
                continue;
            }
            // Reject connections from other processes
            if (!IsConnectionFromSteam(clientFd)) {
                close(clientFd);
                continue;
            }
            // Set socket timeouts to prevent stalled clients from blocking threads
            struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
            setsockopt(clientFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(clientFd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            // Reject if too many concurrent connections (local DoS protection)
            if (g_activeConnections.load() >= MAX_CONCURRENT_CONNECTIONS) {
                const char* resp = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n";
                send(clientFd, resp, strlen(resp), 0);
                close(clientFd);
                continue;
            }
            // Handle in a tracked thread
            {
                std::lock_guard<std::mutex> lock(g_clientMutex);
                // Clean up finished threads
                g_clientThreads.erase(
                    std::remove_if(g_clientThreads.begin(), g_clientThreads.end(),
                        [](ClientThread& client) {
                            if (client.done->load(std::memory_order_acquire)) {
                                if (client.thread.joinable()) client.thread.join();
                                return true;
                            }
                            return false;
                        }),
                    g_clientThreads.end());
                auto done = std::make_shared<std::atomic<bool>>(false);
                try {
                    RegisterClientFd(clientFd);
                    g_clientThreads.push_back(ClientThread{std::thread([clientFd, done]() {
                        g_activeConnections.fetch_add(1);
                        HandleConnection(clientFd);
                        UnregisterClientFd(clientFd);
                        g_activeConnections.fetch_sub(1);
                        done->store(true, std::memory_order_release);
                    }), done});
                } catch (...) {
                    LOG("[HttpServer] Failed to create client thread");
                    UnregisterClientFd(clientFd);
                    close(clientFd);
                }
            }
        }
    });

    LOG("[HttpServer] Started on 127.0.0.1:%u, blobRoot=%s", g_port, blobRoot.c_str());
    return true;
}

void SetAccountId(uint32_t accountId) {
    g_accountId = accountId;
}

void SetMaxUploadMB(int mb) {
    if (mb <= 0) return;
    // Cast before multiplication to prevent signed overflow
    g_maxUploadBytes.store(static_cast<uint64_t>(mb) * 1024ULL * 1024ULL, std::memory_order_relaxed);
    LOG("[HttpServer] SetMaxUploadMB: %d MB", mb);
}

void Stop() {
    g_running = false;
    if (g_listenFd >= 0) {
        shutdown(g_listenFd, SHUT_RDWR);
        close(g_listenFd);
        g_listenFd = -1;
    }
    if (g_serverThread.joinable())
        g_serverThread.join();
    {
        std::lock_guard<std::mutex> lock(g_clientFdMutex);
        for (int fd : g_clientFds) {
            shutdown(fd, SHUT_RDWR);
        }
    }
    {
        std::lock_guard<std::mutex> lock(g_clientMutex);
        for (auto& client : g_clientThreads) {
            if (client.thread.joinable()) client.thread.join();
        }
        g_clientThreads.clear();
    }
    g_port = 0;
}

uint16_t GetPort() {
    return g_port;
}

bool HasBlob(uint32_t accountId, uint32_t appId, const std::string& filename) {
    std::string path = BlobPath(accountId, appId, filename);
    if (!FileUtil::IsPathWithin(g_blobRoot, path)) return false;
    std::error_code ec;
    return std::filesystem::exists(path, ec);
}

uint64_t GetBlobSize(uint32_t accountId, uint32_t appId, const std::string& filename) {
    std::string path = BlobPath(accountId, appId, filename);
    if (!FileUtil::IsPathWithin(g_blobRoot, path)) return 0;
    std::error_code ec;
    auto sz = std::filesystem::file_size(path, ec);
    return ec ? 0 : sz;
}

std::vector<uint8_t> ReadBlob(uint32_t accountId, uint32_t appId, const std::string& filename) {
    std::string path = BlobPath(accountId, appId, filename);
    if (!FileUtil::IsPathWithin(g_blobRoot, path)) return {};
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return {};
    auto size = f.tellg();
    if (size == std::streampos(-1) || size <= 0) return {};
    std::vector<uint8_t> buf(static_cast<size_t>(size));
    f.seekg(0);
    if (!f) return {};
    f.read(reinterpret_cast<char*>(buf.data()), size);
    return buf;
}

bool DeleteBlob(uint32_t accountId, uint32_t appId, const std::string& filename) {
    std::string path = BlobPath(accountId, appId, filename);
    if (!FileUtil::IsPathWithin(g_blobRoot, path)) return false;
    std::error_code ec;
    return std::filesystem::remove(path, ec);
}

} // namespace HttpServer
