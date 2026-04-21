#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace HttpServer {

// start blob HTTP server on 127.0.0.1 (OS-assigned port). Handles PUT/GET for blob upload/download.
bool Start(const std::string& blobRoot, uint32_t accountId = 0);

// set the account ID for blob path namespacing (called when SteamID is captured from first RPC)
void SetAccountId(uint32_t accountId);

// set the max upload size in MB. 0 = unlimited. default is 256 MB.
void SetMaxUploadMB(int mb);

// stop the server and join the background thread
void Stop();

// get the port the server bound to (0 if not started)
uint16_t GetPort();

// check if a blob exists for the given account/app/filename
bool HasBlob(uint32_t accountId, uint32_t appId, const std::string& filename);

// get the size of a stored blob (compressed size on disk). returns 0 if not found.
uint64_t GetBlobSize(uint32_t accountId, uint32_t appId, const std::string& filename);

// read a stored blob into memory. returns empty vector if not found.
std::vector<uint8_t> ReadBlob(uint32_t accountId, uint32_t appId, const std::string& filename);

// delete a stored blob. returns true if it existed and was removed.
bool DeleteBlob(uint32_t accountId, uint32_t appId, const std::string& filename);

// write a blob directly (used for seeding/migration, not normal upload path).
bool WriteBlob(uint32_t accountId, uint32_t appId, const std::string& filename,
               const uint8_t* data, size_t len);

} // namespace HttpServer
