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

// Locate a nested VDF section body by walking sectionPath. On success sets
// [sectionStart, sectionEnd) to the byte range between the opening and closing
// braces of the deepest section (sectionStart points to the byte after '{';
// sectionEnd points to the matching '}'). Returns false if any segment of the
// path is missing or if braces don't balance.
//
// The header search is anchored on a line-start: a quoted appid/key buried
// inside a value string will NOT match. This is the contract downstream
// callers (e.g. remotecache.vdf repair) rely on to avoid misaligning their
// section boundaries when future Steam versions add pre-section metadata.
bool FindVdfSectionRange(const std::string& vdfContent,
                         const char* const* sectionPath, size_t pathLen,
                         size_t& sectionStart, size_t& sectionEnd);

// Callback receives the name of each direct child of the target section --
// both scalar fields ("key" "value") and sub-section headers ("name" { ... }).
// Return false to stop iteration early. Unlike ForEachFieldInSection this
// reports sub-section headers too, which is what callers enumerating e.g.
// remotecache.vdf's per-file entries need (each file is a sub-section, not a
// scalar field).
//
// Tolerates CRLF line endings and blank lines between a header and its
// opening brace. Does NOT support '{' on the same line as its key -- Steam's
// writer always puts the brace on a new line, and accepting same-line braces
// would admit ambiguity around quoted strings that contain '{'.
using ChildCallback = std::function<bool(std::string_view name)>;
bool ForEachChildInSection(const std::string& vdfContent,
                           const char* const* sectionPath, size_t pathLen,
                           ChildCallback cb);

} // namespace VdfUtil
