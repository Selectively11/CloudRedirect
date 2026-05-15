#include "protobuf.h"
#include <cstring>

namespace PB {

size_t DecodeVarint(const uint8_t* buf, size_t bufLen, uint64_t& out) {
    out = 0;
    for (size_t i = 0; i < bufLen && i < 10; ++i) {
        out |= (uint64_t)(buf[i] & 0x7F) << (7 * i);
        if (!(buf[i] & 0x80))
            return i + 1;
    }
    return 0; // malformed
}

size_t EncodeVarint(uint8_t* buf, uint64_t value) {
    size_t i = 0;
    do {
        buf[i] = value & 0x7F;
        value >>= 7;
        if (value) buf[i] |= 0x80;
        ++i;
    } while (value);
    return i;
}

std::vector<Field> Parse(const uint8_t* buf, size_t bufLen) {
    std::vector<Field> fields;
    size_t pos = 0;

    while (pos < bufLen) {
        uint64_t tag;
        size_t n = DecodeVarint(buf + pos, bufLen - pos, tag);
        if (!n) break;
        pos += n;

        Field f{};
        f.fieldNum = (uint32_t)(tag >> 3);
        f.wireType = (WireType)(tag & 7);

        switch (f.wireType) {
        case Varint: {
            n = DecodeVarint(buf + pos, bufLen - pos, f.varintVal);
            if (!n) goto done;
            pos += n;
            break;
        }
        case Fixed64: {
            if (pos + 8 > bufLen) goto done;
            memcpy(&f.varintVal, buf + pos, 8);
            pos += 8;
            break;
        }
        case Fixed32: {
            if (pos + 4 > bufLen) goto done;
            uint32_t v;
            memcpy(&v, buf + pos, 4);
            f.varintVal = v;
            pos += 4;
            break;
        }
        case LengthDelimited: {
            uint64_t len;
            n = DecodeVarint(buf + pos, bufLen - pos, len);
            if (!n) goto done;
            pos += n;
            if (len > bufLen - pos) goto done;  // overflow-safe check
            f.data = buf + pos;
            f.dataLen = (len > UINT32_MAX) ? UINT32_MAX : (uint32_t)len;
            pos += (size_t)len;
            break;
        }
        default:
            goto done; // unknown wire type
        }

        fields.push_back(f);
    }
done:
    return fields;
}

const Field* FindField(const std::vector<Field>& fields, uint32_t fieldNum) {
    for (auto& f : fields) {
        if (f.fieldNum == fieldNum)
            return &f;
    }
    return nullptr;
}

std::string_view GetString(const std::vector<Field>& fields, uint32_t fieldNum) {
    auto* f = FindField(fields, fieldNum);
    if (!f || f->wireType != LengthDelimited) return {};
    return { (const char*)f->data, f->dataLen };
}

// Writer implementation

void Writer::WriteTag(uint32_t fieldNum, WireType wt) {
    WriteRawVarint((uint64_t(fieldNum) << 3) | wt);
}

void Writer::WriteRawVarint(uint64_t value) {
    uint8_t tmp[10];
    size_t n = EncodeVarint(tmp, value);
    buf_.insert(buf_.end(), tmp, tmp + n);
}

void Writer::WriteVarint(uint32_t fieldNum, uint64_t value) {
    WriteTag(fieldNum, Varint);
    WriteRawVarint(value);
}

void Writer::WriteFixed64(uint32_t fieldNum, uint64_t value) {
    WriteTag(fieldNum, Fixed64);
    size_t pos = buf_.size();
    buf_.resize(pos + 8);
    memcpy(buf_.data() + pos, &value, 8);
}

void Writer::WriteBytes(uint32_t fieldNum, const uint8_t* data, size_t len) {
    WriteTag(fieldNum, LengthDelimited);
    WriteRawVarint(len);
    buf_.insert(buf_.end(), data, data + len);
}

void Writer::WriteString(uint32_t fieldNum, std::string_view str) {
    WriteBytes(fieldNum, (const uint8_t*)str.data(), str.size());
}

void Writer::WriteSubmessage(uint32_t fieldNum, const Writer& sub) {
    WriteBytes(fieldNum, sub.buf_.data(), sub.buf_.size());
}

} // namespace PB
