#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <string_view>

// Minimal protobuf encoder/decoder for Steam IPC messages.
// Only supports the wire types we actually need.

namespace PB {

enum WireType : uint8_t {
    Varint = 0,
    Fixed64 = 1,
    LengthDelimited = 2,
    Fixed32 = 5,
};

size_t DecodeVarint(const uint8_t* buf, size_t bufLen, uint64_t& out);
size_t EncodeVarint(uint8_t* buf, uint64_t value);
size_t VarintSize(uint64_t value);

struct Field {
    uint32_t fieldNum = 0;
    WireType wireType = Varint;
    uint64_t varintVal = 0;          // for Varint, Fixed32, Fixed64
    const uint8_t* data = nullptr;   // for LengthDelimited
    uint32_t dataLen = 0;            // for LengthDelimited
};

std::vector<Field> Parse(const uint8_t* buf, size_t bufLen);
const Field* FindField(const std::vector<Field>& fields, uint32_t fieldNum);
std::string_view GetString(const std::vector<Field>& fields, uint32_t fieldNum);

class Writer {
public:
    // NOTE: When emitting a Steam UFS field that the IDA-audited descriptor
    // declares as `optional uint32` (e.g. raw_file_size, file_size,
    // existing_files), route the value through ClampFileSizeToUint32 in
    // rpc_handlers.cpp instead of passing a raw uint64. Steam's parser
    // narrows on read and silently truncates mod 2^32; the helper logs
    // and clamps so a bad value pinpoints the offending field/file.
    void WriteVarint(uint32_t fieldNum, uint64_t value);
    void WriteFixed64(uint32_t fieldNum, uint64_t value);
    void WriteFixed32(uint32_t fieldNum, uint32_t value);
    void WriteBytes(uint32_t fieldNum, const uint8_t* data, size_t len);
    void WriteString(uint32_t fieldNum, std::string_view str);
    void WriteSubmessage(uint32_t fieldNum, const Writer& sub);

    const std::vector<uint8_t>& Data() const { return buf_; }
    size_t Size() const { return buf_.size(); }

private:
    void WriteTag(uint32_t fieldNum, WireType wt);
    void WriteRawVarint(uint64_t value);

    std::vector<uint8_t> buf_;
};

} // namespace PB
