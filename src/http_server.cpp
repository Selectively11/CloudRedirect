#include "http_server.h"
#include "http_util.h"
#include "file_util.h"
#include "log.h"

#include "miniz.h"

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <tcpmib.h>
#include <thread>
#include <atomic>
#include <mutex>
#include <memory>
#include <vector>
#include <filesystem>
#include <fstream>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace HttpServer {

static const char* stristr(const char* haystack, const char* needle) {
    if (!haystack || !needle) return nullptr;
    size_t nlen = strlen(needle);
    for (; *haystack; ++haystack) {
        if (_strnicmp(haystack, needle, nlen) == 0)
            return haystack;
    }
    return nullptr;
}

static SOCKET g_listenSock = INVALID_SOCKET;
static std::atomic<uint16_t> g_port{0};
static std::thread g_acceptThread;
static std::atomic<bool> g_running{false};
static std::string g_blobRoot; // persistent blob storage directory
static std::atomic<uint32_t> g_accountId{0}; // Steam account ID for namespace isolation
static std::atomic<int64_t> g_maxUploadBytes{256 * 1024 * 1024}; // 256 MB default, 0 = unlimited
static std::mutex g_clientMtx;

struct ClientSlot {
    std::thread                    thread;
    std::shared_ptr<std::atomic<bool>> done;
};
static std::vector<ClientSlot> g_clientSlots;

// Try to decompress a ZIP archive produced by Steam's cloud compression.
// Returns true if the data was a ZIP and was successfully decompressed (output in 'out').
// Returns false if the data is not a ZIP or decompression fails; caller should store as-is.
static bool TryDecompressZip(const std::vector<uint8_t>& data, std::vector<uint8_t>& out) {
    if (data.size() < 4) return false;
    if (data[0] != 0x50 || data[1] != 0x4B || data[2] != 0x03 || data[3] != 0x04)
        return false;

    mz_zip_archive zip{};
    if (!mz_zip_reader_init_mem(&zip, data.data(), data.size(), 0)) {
        LOG("[HTTP] ZIP init failed: %s", mz_zip_get_error_string(mz_zip_get_last_error(&zip)));
        return false;
    }

    // Steam's cloud compression always produces a single-entry ZIP with
    // inner filename "z". Reject anything else to avoid decompressing
    // game saves that are natively ZIP archives.
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

    // Reject if declared uncompressed size exceeds 512 MB
    if (fstat.m_uncomp_size > 512ULL * 1024 * 1024) {
        LOG("[HTTP] ZIP rejected: declared size %llu", (unsigned long long)fstat.m_uncomp_size);
        mz_zip_reader_end(&zip);
        return false;
    }

    size_t uncompSize = 0;
    void* p = mz_zip_reader_extract_to_heap(&zip, 0, &uncompSize, 0);
    mz_zip_reader_end(&zip);

    if (!p) {
        LOG("[HTTP] ZIP extract failed");
        return false;
    }

    out.assign(static_cast<uint8_t*>(p), static_cast<uint8_t*>(p) + uncompSize);
    mz_free(p);
    return true;
}

// Remove finished client threads (call with g_clientMtx held)
static void PruneClientThreads() {
    std::vector<ClientSlot> alive;
    alive.reserve(g_clientSlots.size());
    for (auto& slot : g_clientSlots) {
        if (slot.done->load()) {
            if (slot.thread.joinable()) slot.thread.join();
        } else {
            alive.push_back(std::move(slot));
        }
    }
    g_clientSlots = std::move(alive);
}

// get the filesystem path for a blob: <blobRoot>/<accountId>/<appId>/<filename>
static std::string BlobPath(uint32_t appId, const std::string& filename) {
    std::string path = g_blobRoot + std::to_string(g_accountId.load()) + "\\" +
                       std::to_string(appId) + "\\" + filename;
    for (auto& c : path) { if (c == '/') c = '\\'; }
    return path;
}

// parse a URL path like "/upload/12345/saves/game.sav" into appId + filename.
// prefix is "/upload/" or "/download/".
// returns true if parse succeeded.
// rejects path traversal attempts (e.g. "../" sequences after URL decoding).
static bool ParseBlobPath(const char* path, const char* prefix,
                          uint32_t& appId, std::string& filename) {
    size_t prefixLen = strlen(prefix);
    if (strncmp(path, prefix, prefixLen) != 0) return false;

    const char* rest = path + prefixLen;
    // parse appId (digits until next '/')
    char* slash = nullptr;
    unsigned long id = strtoul(rest, &slash, 10);
    if (!slash || *slash != '/' || id == 0) return false;

    appId = (uint32_t)id;
    std::string rawPath(slash + 1);
    // Strip query string (e.g. ?raw=12345)
    auto qpos = rawPath.find('?');
    if (qpos != std::string::npos) rawPath.resize(qpos);
    filename = HttpUtil::UrlDecode(rawPath);
    if (filename.empty()) return false;

    // Validate: resolved blob path must stay within the blob root.
    std::string blobPath = BlobPath(appId, filename);
    if (!FileUtil::IsPathWithin(g_blobRoot, blobPath)) {
        LOG("[HTTP] BLOCKED path traversal: %s (root=%s)", path, g_blobRoot.c_str());
        return false;
    }

    return true;
}

// handle one accepted connection: parse request line, dispatch GET or PUT
static void HandleClient(SOCKET client) {
    // read headers line by line until we see the blank line (\r\n\r\n)
    // Cap header accumulation at 64KB to prevent abuse
    static constexpr int MAX_HEADER_SIZE = 65536;
    char buf[8192];
    int total = 0;
    int headerEnd = -1;

    while (total < (int)sizeof(buf) - 1 && total < MAX_HEADER_SIZE) {
        int n = recv(client, buf + total, (int)sizeof(buf) - 1 - total, 0);
        if (n <= 0) break;
        total += n;
        buf[total] = '\0';

        char* found = strstr(buf, "\r\n\r\n");
        if (found) {
            headerEnd = (int)(found - buf) + 4;
            break;
        }
    }

    if (headerEnd < 0) {
        closesocket(client);
        return;
    }

    // parse request line: "METHOD /path HTTP/1.1\r\n"
    char method[16] = {};
    char path[2048] = {};
    sscanf(buf, "%15s %2047s", method, path);

    // parse Content-Length from headers (case-insensitive)
    int64_t contentLength = -1; // -1 = not present
    const char* cl = stristr(buf, "Content-Length:");
    if (cl) {
        contentLength = _strtoi64(cl + 15, nullptr, 10);
        if (contentLength < 0) contentLength = 0;
    }

    int bodyReceived = total - headerEnd;

    if (_stricmp(method, "PUT") == 0) {
        // Reject PUT without Content-Length — we can't safely read the body
        if (contentLength < 0) {
            LOG("[HTTP] PUT %s -> REJECTED: no Content-Length header", path);
            const char* response =
                "HTTP/1.1 411 Length Required\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n"
                "\r\n";
            send(client, response, (int)strlen(response), 0);
            closesocket(client);
            return;
        }

        // PUT /upload/<appId>/<filename>
        int64_t maxBytes = g_maxUploadBytes.load();
        if (maxBytes > 0 && contentLength > maxBytes) {
            LOG("[HTTP] PUT %s -> REJECTED: Content-Length %lld exceeds %lld byte cap",
                path, contentLength, maxBytes);
            const char* response =
                "HTTP/1.1 413 Payload Too Large\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n"
                "\r\n";
            send(client, response, (int)strlen(response), 0);
            closesocket(client);
            return;
        }

        uint32_t appId = 0;
        std::string filename;

        if (ParseBlobPath(path, "/upload/", appId, filename)) {
            // read the full body
            std::vector<uint8_t> bodyData;
            bodyData.reserve(contentLength > 0 ? (size_t)contentLength : 4096);

            // copy any body bytes already received with the headers
            if (bodyReceived > 0)
                bodyData.insert(bodyData.end(), buf + headerEnd, buf + headerEnd + bodyReceived);

            // read remaining body
            int64_t remaining = contentLength - bodyReceived;
            if (remaining > 0) {
                char chunk[65536];
                while (remaining > 0) {
                    int toRead = remaining < (int64_t)sizeof(chunk) ? (int)remaining : (int)sizeof(chunk);
                    int n = recv(client, chunk, toRead, 0);
                    if (n <= 0) break;
                    bodyData.insert(bodyData.end(), chunk, chunk + n);
                    remaining -= n;
                }
            }

            // Reject partial body — recv returned 0/-1 before all bytes arrived
            if (contentLength > 0 && (int64_t)bodyData.size() != contentLength) {
                LOG("[HTTP] PUT %s -> PARTIAL BODY (%zu of %lld bytes), rejecting",
                    path, bodyData.size(), (long long)contentLength);
                const char* errResponse =
                    "HTTP/1.1 400 Bad Request\r\n"
                    "Content-Length: 0\r\n"
                    "Connection: close\r\n"
                    "\r\n";
                send(client, errResponse, (int)strlen(errResponse), 0);
                shutdown(client, SD_SEND);
                closesocket(client);
                return;
            }

            // Steam may send compressed (ZIP) data. Decompress before storing
            // so blob storage always contains raw file content.
            std::vector<uint8_t> decompressed;
            if (TryDecompressZip(bodyData, decompressed)) {
                LOG("[HTTP] PUT %s -> decompressed %zu -> %zu bytes",
                    path, bodyData.size(), decompressed.size());
                bodyData = std::move(decompressed);
            }

            // write blob to disk
            std::string blobPath = BlobPath(appId, filename);
            auto parent = std::filesystem::path(blobPath).parent_path();
            std::filesystem::create_directories(parent);

            // Atomic write blob to disk
            if (!FileUtil::AtomicWriteBinary(blobPath, bodyData.data(), bodyData.size())) {
                LOG("[HTTP] PUT %s -> WRITE FAILED for %s", path, blobPath.c_str());
                const char* errResponse =
                    "HTTP/1.1 500 Internal Server Error\r\n"
                    "Content-Length: 0\r\n"
                    "Connection: close\r\n"
                    "\r\n";
                send(client, errResponse, (int)strlen(errResponse), 0);
                shutdown(client, SD_SEND);
                closesocket(client);
                return;
            }
            LOG("[HTTP] PUT %s -> stored %zu bytes (app %u, file %s)",
                path, bodyData.size(), appId, filename.c_str());

            // return 200 OK (matches what Steam expects from Valve's storage)
            const char* response =
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n"
                "\r\n";
            send(client, response, (int)strlen(response), 0);
        } else {
            // unrecognized PUT path — drain and return 200 OK
            int64_t remaining = contentLength - bodyReceived;
            if (remaining > 0) {
                char drain[4096];
                while (remaining > 0) {
                    int chunk = remaining < (int64_t)sizeof(drain) ? (int)remaining : (int)sizeof(drain);
                    int n = recv(client, drain, chunk, 0);
                    if (n <= 0) break;
                    remaining -= n;
                }
            }
            LOG("[HTTP] PUT %s -> unrecognized path, drained %lld bytes", path, contentLength);
            const char* response =
                "HTTP/1.1 404 Not Found\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n"
                "\r\n";
            send(client, response, (int)strlen(response), 0);
        }
    } else if (_stricmp(method, "GET") == 0) {
        // GET /download/<appId>/<filename>
        uint32_t appId = 0;
        std::string filename;

        if (ParseBlobPath(path, "/download/", appId, filename)) {
            std::string blobPath = BlobPath(appId, filename);
            std::ifstream f(blobPath, std::ios::binary | std::ios::ate);

            if (f) {
                auto pos = f.tellg();
                if (pos == std::streampos(-1)) {
                    LOG("[HTTP] GET %s -> tellg() failed for %s", path, blobPath.c_str());
                    const char* resp500 =
                        "HTTP/1.1 500 Internal Server Error\r\n"
                        "Content-Length: 0\r\n"
                        "Connection: close\r\n"
                        "\r\n";
                    send(client, resp500, (int)strlen(resp500), 0);
                    shutdown(client, SD_SEND);
                    closesocket(client);
                    return;
                }
                size_t fileSize = (size_t)pos;
                f.seekg(0);

                LOG("[HTTP] GET %s -> serving %zu bytes (app %u, file %s)",
                    path, fileSize, appId, filename.c_str());

                char respHeader[256];
                snprintf(respHeader, sizeof(respHeader),
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Length: %zu\r\n"
                    "Connection: close\r\n"
                    "\r\n", fileSize);
                send(client, respHeader, (int)strlen(respHeader), 0);

                char chunk[65536];
                size_t sent = 0;
                while (sent < fileSize) {
                    size_t toRead = min(fileSize - sent, sizeof(chunk));
                    f.read(chunk, toRead);
                    auto got = (size_t)f.gcount();
                    if (got == 0) break;
                    size_t chunkSent = 0;
                    while (chunkSent < got) {
                        int n = send(client, chunk + chunkSent, (int)(got - chunkSent), 0);
                        if (n <= 0) goto done_sending;
                        chunkSent += n;
                    }
                    sent += got;
                }
                done_sending:
                f.close();
                LOG("[HTTP] GET %s -> sent %zu/%zu bytes", path, sent, fileSize);
            } else {
                LOG("[HTTP] GET %s -> 404 blob not found: %s", path, blobPath.c_str());
                const char* resp404 =
                    "HTTP/1.1 404 Not Found\r\n"
                    "Content-Length: 0\r\n"
                    "Connection: close\r\n"
                    "\r\n";
                send(client, resp404, (int)strlen(resp404), 0);
            }
        } else {
            LOG("[HTTP] GET %s -> 404 unrecognized path", path);
            const char* resp404 =
                "HTTP/1.1 404 Not Found\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n"
                "\r\n";
            send(client, resp404, (int)strlen(resp404), 0);
        }
    } else {
        // unrecognized method: drain body, return 405
        LOG("[HTTP] %s %s -> 405 method not allowed", method, path);
        int64_t remaining = contentLength > 0 ? contentLength - bodyReceived : 0;
        if (remaining > 0) {
            char drain[4096];
            while (remaining > 0) {
                int chunk = remaining < (int64_t)sizeof(drain) ? (int)remaining : (int)sizeof(drain);
                int n = recv(client, drain, chunk, 0);
                if (n <= 0) break;
                remaining -= n;
            }
        }
        const char* response =
            "HTTP/1.1 405 Method Not Allowed\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        send(client, response, (int)strlen(response), 0);
    }

    shutdown(client, SD_SEND);
    closesocket(client);
}

// Validate that the connecting client is our own process (Steam).
// Uses GetExtendedTcpTable to look up the PID that owns the client's source port.
static bool IsConnectionFromSteam(SOCKET client) {
    // Get the peer's (client's) port
    sockaddr_in peer{};
    int peerLen = sizeof(peer);
    if (getpeername(client, (sockaddr*)&peer, &peerLen) != 0) return false;
    uint16_t peerPort = ntohs(peer.sin_port);

    DWORD myPid = GetCurrentProcessId();

    // Get the TCP connection table with PIDs
    DWORD tableSize = 0;
    GetExtendedTcpTable(nullptr, &tableSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
    if (tableSize == 0) return false;

    std::vector<uint8_t> tableBuf(tableSize);
    if (GetExtendedTcpTable(tableBuf.data(), &tableSize, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_CONNECTIONS, 0) != NO_ERROR) {
        return false;
    }

    auto* table = (MIB_TCPTABLE_OWNER_PID*)tableBuf.data();
    for (DWORD i = 0; i < table->dwNumEntries; i++) {
        auto& row = table->table[i];
        // Match: local port (peer's source port) and established state
        if (ntohs((uint16_t)row.dwLocalPort) == peerPort &&
            row.dwState == MIB_TCP_STATE_ESTAB) {
            if (row.dwOwningPid == myPid) return true;
            LOG("[HTTP] BLOCKED connection from PID %u (expected %u) on port %u",
                row.dwOwningPid, myPid, peerPort);
            return false;
        }
    }

    // Connection not found in table — race condition, reject to be safe
    return false;
}

static void AcceptLoop() {
    LOG("[HTTP] Accept loop started on port %u", g_port.load());
    while (g_running.load()) {
        // use select with a timeout so we can check g_running periodically
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(g_listenSock, &readfds);

        timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int sel = select(0, &readfds, nullptr, nullptr, &tv);
        if (sel <= 0) continue;

        SOCKET client = accept(g_listenSock, nullptr, nullptr);
        if (client == INVALID_SOCKET) continue;

        // Reject connections from other processes
        if (!IsConnectionFromSteam(client)) {
            closesocket(client);
            continue;
        }

        // Set receive timeout to prevent slow/stalled clients from blocking a thread
        DWORD rcvTimeout = 30000; // 30 seconds
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (const char*)&rcvTimeout, sizeof(rcvTimeout));

        // handle each connection on its own thread so parallel uploads don't queue up
        {
            std::lock_guard<std::mutex> lk(g_clientMtx);
            PruneClientThreads();

            // Cap active client threads to prevent resource exhaustion
            if (g_clientSlots.size() >= 16) {
                LOG("[HTTP] Max client threads reached (16), rejecting connection");
                closesocket(client);
                continue;
            }

            auto doneFlag = std::make_shared<std::atomic<bool>>(false);
            auto wrapper = [doneFlag](SOCKET s) {
                HandleClient(s);
                doneFlag->store(true);
            };
            g_clientSlots.push_back({std::thread(wrapper, client), doneFlag});
        }
    }
    LOG("[HTTP] Accept loop exited");
}

bool Start(const std::string& blobRoot, uint32_t accountId) {
    g_blobRoot = blobRoot;
    g_accountId.store(accountId);
    if (!g_blobRoot.empty() && g_blobRoot.back() != '\\')
        g_blobRoot += '\\';
    std::filesystem::create_directories(g_blobRoot);
    LOG("[HTTP] Blob storage root: %s (accountId=%u)", g_blobRoot.c_str(), g_accountId.load());

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        LOG("[HTTP] WSAStartup failed: %d", WSAGetLastError());
        return false;
    }

    g_listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_listenSock == INVALID_SOCKET) {
        LOG("[HTTP] socket() failed: %d", WSAGetLastError());
        return false;
    }

    // bind to 127.0.0.1 with OS-assigned port
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0; // OS picks a free port

    if (bind(g_listenSock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        LOG("[HTTP] bind() failed: %d", WSAGetLastError());
        closesocket(g_listenSock);
        g_listenSock = INVALID_SOCKET;
        return false;
    }

    // retrieve the assigned port
    sockaddr_in bound{};
    int boundLen = sizeof(bound);
    getsockname(g_listenSock, (sockaddr*)&bound, &boundLen);
    g_port.store(ntohs(bound.sin_port));

    if (listen(g_listenSock, SOMAXCONN) == SOCKET_ERROR) {
        LOG("[HTTP] listen() failed: %d", WSAGetLastError());
        closesocket(g_listenSock);
        g_listenSock = INVALID_SOCKET;
        return false;
    }

    g_running.store(true);
    g_acceptThread = std::thread(AcceptLoop);

    LOG("[HTTP] Server started on 127.0.0.1:%u", g_port.load());
    return true;
}

void Stop() {
    if (!g_running.load()) return;

    g_running.store(false);

    if (g_listenSock != INVALID_SOCKET) {
        closesocket(g_listenSock);
        g_listenSock = INVALID_SOCKET;
    }

    if (g_acceptThread.joinable())
        g_acceptThread.join();

    // Wait for in-flight client handlers to finish
    {
        std::lock_guard<std::mutex> lk(g_clientMtx);
        for (auto& slot : g_clientSlots) {
            if (slot.thread.joinable()) slot.thread.join();
        }
        g_clientSlots.clear();
    }

    WSACleanup();
    LOG("[HTTP] Server stopped");
}

void SetAccountId(uint32_t accountId) {
    g_accountId.store(accountId);
    LOG("[HTTP] Account ID set to %u", g_accountId.load());
}

void SetMaxUploadMB(int mb) {
    g_maxUploadBytes.store(mb > 0 ? (int64_t)mb * 1024 * 1024 : 0);
    if (mb > 0)
        LOG("[HTTP] Max upload cap set to %d MB", mb);
    else
        LOG("[HTTP] Max upload cap disabled (unlimited)");
}

uint16_t GetPort() {
    return g_port.load();
}

// Validate that a resolved blob path stays within the blob root.
// Same traversal check as ParseBlobPath, used by the RPC-facing functions below.
static bool ValidateBlobPath(const std::string& blobPath) {
    if (!FileUtil::IsPathWithin(g_blobRoot, blobPath)) {
        LOG("[HTTP] BLOCKED path traversal (RPC): path='%s' root='%s'",
            blobPath.c_str(), g_blobRoot.c_str());
        return false;
    }
    return true;
}

bool HasBlob(uint32_t appId, const std::string& filename) {
    std::string path = BlobPath(appId, filename);
    if (!ValidateBlobPath(path)) return false;
    return std::filesystem::exists(path);
}

uint64_t GetBlobSize(uint32_t appId, const std::string& filename) {
    std::string path = BlobPath(appId, filename);
    if (!ValidateBlobPath(path)) return 0;
    std::error_code ec;
    auto sz = std::filesystem::file_size(path, ec);
    return ec ? 0 : (uint64_t)sz;
}

std::vector<uint8_t> ReadBlob(uint32_t appId, const std::string& filename) {
    std::string path = BlobPath(appId, filename);
    if (!ValidateBlobPath(path)) return {};
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    return std::vector<uint8_t>(
        std::istreambuf_iterator<char>(f),
        std::istreambuf_iterator<char>()
    );
}

bool DeleteBlob(uint32_t appId, const std::string& filename) {
    std::string path = BlobPath(appId, filename);
    if (!ValidateBlobPath(path)) return false;
    std::error_code ec;
    return std::filesystem::remove(path, ec);
}

bool WriteBlob(uint32_t appId, const std::string& filename,
               const uint8_t* data, size_t len) {
    std::string path = BlobPath(appId, filename);
    if (!ValidateBlobPath(path)) return false;
    auto parent = std::filesystem::path(path).parent_path();
    std::filesystem::create_directories(parent);
    return FileUtil::AtomicWriteBinary(path, data, len);
}

} // namespace HttpServer
