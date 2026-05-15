#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace Json {

enum class Type { Null, Bool, Number, String, Array, Object };

struct Value {
    Type type = Type::Null;
    bool boolVal = false;
    double numVal = 0;
    std::string strVal;
    std::vector<Value> arrVal;
    std::unordered_map<std::string, Value> objVal;

    const Value& operator[](const char* key) const;
    const Value& operator[](const std::string& key) const;
    const Value& operator[](size_t idx) const;
    bool has(const std::string& key) const;

    const std::string& str() const { return strVal; }
    int64_t integer() const { return (int64_t)numVal; }
    double number() const { return numVal; }
    bool boolean() const { return boolVal; }
    size_t size() const;
    bool isNull() const { return type == Type::Null; }
};

Value Parse(const std::string& json);
std::string Stringify(const Value& val);

// builders
Value String(const std::string& s);
Value Number(double n);
Value Array();
Value Object();

} // namespace Json
