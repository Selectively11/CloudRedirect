#include "json.h"
#include <cstring>
#include <cstdio>

namespace Json {

static const Value g_null;

const Value& Value::operator[](const char* key) const {
    return (*this)[std::string(key)];
}

const Value& Value::operator[](const std::string& key) const {
    if (type != Type::Object) return g_null;
    auto it = objVal.find(key);
    return (it != objVal.end()) ? it->second : g_null;
}

const Value& Value::operator[](size_t idx) const {
    if (type != Type::Array || idx >= arrVal.size()) return g_null;
    return arrVal[idx];
}

bool Value::has(const std::string& key) const {
    return type == Type::Object && objVal.count(key) > 0;
}

size_t Value::size() const {
    if (type == Type::Array) return arrVal.size();
    if (type == Type::Object) return objVal.size();
    return 0;
}

// recursive descent parser
struct Parser {
    const char* s;
    size_t pos;
    size_t len;
    int depth = 0;
    static constexpr int MAX_DEPTH = 64;

    void skipWs() {
        while (pos < len) {
            if (s[pos]==' '||s[pos]=='\t'||s[pos]=='\n'||s[pos]=='\r') {
                ++pos;
            } else if (pos + 1 < len && s[pos] == '/' && s[pos+1] == '/') {
                pos += 2;
                while (pos < len && s[pos] != '\n') ++pos;
            } else {
                break;
            }
        }
    }

    char peek() { return pos < len ? s[pos] : 0; }
    char next() { return pos < len ? s[pos++] : 0; }

    Value parseValue() {
        skipWs();
        char c = peek();
        if (c == '"') return parseString();
        if (c == '{') return parseObject();
        if (c == '[') return parseArray();
        if (c == 't' || c == 'f') return parseBool();
        if (c == 'n') return parseNull();
        if (c == '-' || (c >= '0' && c <= '9')) return parseNumber();
        return Value();
    }

    Value parseString() {
        next(); // opening "
        Value v;
        v.type = Type::String;
        while (pos < len && s[pos] != '"') {
            if (s[pos] == '\\' && pos + 1 < len) {
                ++pos;
                switch (s[pos]) {
                    case '"': v.strVal += '"'; break;
                    case '\\': v.strVal += '\\'; break;
                    case '/': v.strVal += '/'; break;
                    case 'n': v.strVal += '\n'; break;
                    case 'r': v.strVal += '\r'; break;
                    case 't': v.strVal += '\t'; break;
                    case 'u': {
                        if (pos + 4 < len) {
                            char hex[5] = {s[pos+1],s[pos+2],s[pos+3],s[pos+4],0};
                            unsigned cp = strtoul(hex, nullptr, 16);
                            pos += 4;
                            // handle UTF-16 surrogate pairs (\uD800-\uDBFF \uDC00-\uDFFF)
                            if (cp >= 0xD800 && cp <= 0xDBFF && pos + 2 < len
                                && s[pos+1] == '\\' && s[pos+2] == 'u' && pos + 6 < len) {
                                char hex2[5] = {s[pos+3],s[pos+4],s[pos+5],s[pos+6],0};
                                unsigned lo = strtoul(hex2, nullptr, 16);
                                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                    pos += 6; // skip \uXXXX
                                }
                            }
                            // Lone surrogates (high without low, or bare low) are invalid
                            // in UTF-8. Replace with U+FFFD (replacement character).
                            if (cp >= 0xD800 && cp <= 0xDFFF) {
                                cp = 0xFFFD;
                            }
                            if (cp < 0x80) {
                                v.strVal += (char)cp;
                            } else if (cp < 0x800) {
                                v.strVal += (char)(0xC0 | (cp >> 6));
                                v.strVal += (char)(0x80 | (cp & 0x3F));
                            } else if (cp < 0x10000) {
                                v.strVal += (char)(0xE0 | (cp >> 12));
                                v.strVal += (char)(0x80 | ((cp >> 6) & 0x3F));
                                v.strVal += (char)(0x80 | (cp & 0x3F));
                            } else {
                                v.strVal += (char)(0xF0 | (cp >> 18));
                                v.strVal += (char)(0x80 | ((cp >> 12) & 0x3F));
                                v.strVal += (char)(0x80 | ((cp >> 6) & 0x3F));
                                v.strVal += (char)(0x80 | (cp & 0x3F));
                            }
                        }
                        break;
                    }
                    default: v.strVal += s[pos]; break;
                }
            } else {
                v.strVal += s[pos];
            }
            ++pos;
        }
        if (pos < len) ++pos; // closing "
        return v;
    }

    Value parseNumber() {
        Value v;
        v.type = Type::Number;
        size_t start = pos;
        if (s[pos] == '-') ++pos;
        while (pos < len && s[pos] >= '0' && s[pos] <= '9') ++pos;
        if (pos < len && s[pos] == '.') {
            ++pos;
            while (pos < len && s[pos] >= '0' && s[pos] <= '9') ++pos;
        }
        if (pos < len && (s[pos] == 'e' || s[pos] == 'E')) {
            ++pos;
            if (pos < len && (s[pos] == '+' || s[pos] == '-')) ++pos;
            while (pos < len && s[pos] >= '0' && s[pos] <= '9') ++pos;
        }
        v.numVal = strtod(std::string(s + start, pos - start).c_str(), nullptr);
        return v;
    }

    Value parseBool() {
        Value v;
        v.type = Type::Bool;
        if (s[pos] == 't') {
            v.boolVal = true;
            pos += (pos + 4 <= len) ? 4 : (len - pos);
        } else {
            v.boolVal = false;
            pos += (pos + 5 <= len) ? 5 : (len - pos);
        }
        return v;
    }

    Value parseNull() {
        pos += (pos + 4 <= len) ? 4 : (len - pos);
        return Value();
    }

    Value parseArray() {
        if (depth >= MAX_DEPTH) return Value();
        ++depth;
        next(); // skip [
        Value v;
        v.type = Type::Array;
        skipWs();
        if (peek() == ']') { next(); --depth; return v; }
        while (true) {
            v.arrVal.push_back(parseValue());
            skipWs();
            if (peek() == ',') { next(); continue; }
            if (peek() == ']') { next(); break; }
            break;
        }
        --depth;
        return v;
    }

    Value parseObject() {
        if (depth >= MAX_DEPTH) return Value();
        ++depth;
        next(); // skip {
        Value v;
        v.type = Type::Object;
        skipWs();
        if (peek() == '}') { next(); --depth; return v; }
        while (true) {
            skipWs();
            if (peek() != '"') break; // key must start with quote
            auto key = parseString();
            skipWs();
            next(); // skip :
            auto val = parseValue();
            v.objVal[key.strVal] = std::move(val);
            skipWs();
            if (peek() == ',') { next(); continue; }
            if (peek() == '}') { next(); break; }
            break;
        }
        --depth;
        return v;
    }
};

Value Parse(const std::string& json) {
    Parser p{json.c_str(), 0, json.size()};
    return p.parseValue();
}

static void EscapeStr(const std::string& s, std::string& out) {
    out += '"';
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    // Escape control characters as \u00XX
                    char esc[8];
                    snprintf(esc, sizeof(esc), "\\u%04X", c);
                    out += esc;
                } else {
                    // Pass through printable ASCII (0x20-0x7E) and UTF-8
                    // continuation/lead bytes (>= 0x80) verbatim to preserve
                    // multi-byte sequences
                    out += (char)c;
                }
                break;
        }
    }
    out += '"';
}

static void StringifyImpl(const Value& val, std::string& out, int depth) {
    static constexpr int MAX_DEPTH = 64;
    switch (val.type) {
        case Type::Null: out += "null"; break;
        case Type::Bool: out += val.boolVal ? "true" : "false"; break;
        case Type::Number: {
            if (val.numVal == (double)(int64_t)val.numVal &&
                val.numVal >= -1e15 && val.numVal <= 1e15) {
                char buf[32];
                snprintf(buf, sizeof(buf), "%lld", (long long)(int64_t)val.numVal);
                out += buf;
            } else {
                char buf[32];
                snprintf(buf, sizeof(buf), "%.17g", val.numVal);
                out += buf;
            }
            break;
        }
        case Type::String: EscapeStr(val.strVal, out); break;
        case Type::Array: {
            out += '[';
            if (depth < MAX_DEPTH) {
                for (size_t i = 0; i < val.arrVal.size(); ++i) {
                    if (i > 0) out += ',';
                    StringifyImpl(val.arrVal[i], out, depth + 1);
                }
            }
            out += ']';
            break;
        }
        case Type::Object: {
            out += '{';
            if (depth < MAX_DEPTH) {
                bool first = true;
                for (auto& [k, v] : val.objVal) {
                    if (!first) out += ',';
                    first = false;
                    EscapeStr(k, out);
                    out += ':';
                    StringifyImpl(v, out, depth + 1);
                }
            }
            out += '}';
            break;
        }
    }
}

std::string Stringify(const Value& val) {
    std::string out;
    StringifyImpl(val, out, 0);
    return out;
}

Value String(const std::string& s) {
    Value v; v.type = Type::String; v.strVal = s; return v;
}

Value Number(double n) {
    Value v; v.type = Type::Number; v.numVal = n; return v;
}

Value Array() {
    Value v; v.type = Type::Array; return v;
}

Value Object() {
    Value v; v.type = Type::Object; return v;
}

} // namespace Json
