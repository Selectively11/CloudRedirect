#pragma once
#include <string>
#include <string_view>
#include <functional>

namespace VdfUtil {

struct FieldInfo {
    std::string_view key;
    std::string_view value;
    size_t valStart;    // byte offset of value text (between quotes)
    size_t valEnd;      // byte offset of closing quote
};

// Callback receives each key-value field found inside the target section.
// Return false from callback to stop iteration early.
using FieldCallback = std::function<bool(const FieldInfo&)>;

// Navigate a text VDF to a nested section path (e.g. {"Software","Valve","Steam","Apps","12345"})
// and invoke the callback for each key-value pair in that section.
// Returns true if the section was found, false otherwise.
bool ForEachFieldInSection(const std::string& vdfContent,
                           const char* const* sectionPath, int pathLen,
                           FieldCallback cb);

} // namespace VdfUtil
