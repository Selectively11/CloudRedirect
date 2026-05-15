#ifndef CLOUDREDIRECT_YAML_PARSER_H
#define CLOUDREDIRECT_YAML_PARSER_H

#include <string>
#include <unordered_map>
#include <vector>
#include <fstream>
#include <cctype>

struct YamlValue {
    std::string scalar;
    std::vector<std::string> list;
    bool isList = false;
    bool isBool = false;
    bool boolVal = false;
};

inline std::unordered_map<std::string, YamlValue> ParseYamlFile(const std::string& path) {
    std::unordered_map<std::string, YamlValue> result;
    std::ifstream f(path);
    if (!f) return result;

    std::string line;
    std::string currentKey;
    bool inList = false;

    auto trimLeft = [](const std::string& s) -> std::string {
        size_t i = 0;
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) i++;
        return s.substr(i);
    };

    auto rtrim = [](std::string& s) {
        while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
            s.pop_back();
    };

    auto isBoolTrue = [](const std::string& v) {
        return v == "yes" || v == "true" || v == "1" ||
               v == "Yes" || v == "True" || v == "YES" || v == "TRUE";
    };

    auto isBoolFalse = [](const std::string& v) {
        return v == "no" || v == "false" || v == "0" ||
               v == "No" || v == "False" || v == "NO" || v == "FALSE";
    };

    while (std::getline(f, line)) {
        std::string t = trimLeft(line);
        if (t.empty() || t[0] == '#') continue;

        if (!inList && t[0] == '-' && t.size() >= 2 && t[1] == ' ') {
            std::string item = t.substr(2);
            size_t cpos = item.find('#');
            if (cpos != std::string::npos) item = item.substr(0, cpos);
            rtrim(item);
            if (!currentKey.empty()) {
                result[currentKey].list.push_back(item);
            }
            continue;
        }

        if (inList && !t.empty() && t[0] == '-' && t.size() >= 2 && t[1] == ' ') {
            std::string item = t.substr(2);
            size_t cpos = item.find('#');
            if (cpos != std::string::npos) item = item.substr(0, cpos);
            rtrim(item);
            if (!currentKey.empty()) {
                result[currentKey].list.push_back(item);
            }
            continue;
        }

        size_t colon = t.find(':');
        if (colon == std::string::npos) {
            inList = false;
            currentKey.clear();
            continue;
        }

        std::string key = t.substr(0, colon);
        rtrim(key);
        inList = false;
        currentKey = key;

        std::string value = t.substr(colon + 1);
        size_t vstart = value.find_first_not_of(" \t");
        if (vstart == std::string::npos) {
            result[key].isList = true;
            inList = true;
            continue;
        }

        value = value.substr(vstart);
        size_t cpos = value.find('#');
        if (cpos != std::string::npos) value = value.substr(0, cpos);
        rtrim(value);

        if (value == "~" || value.empty()) {
            continue;
        }

        YamlValue yv;
        if (isBoolTrue(value)) {
            yv.isBool = true;
            yv.boolVal = true;
        } else if (isBoolFalse(value)) {
            yv.isBool = true;
            yv.boolVal = false;
        } else {
            yv.scalar = value;
        }
        result[key] = yv;
    }

    return result;
}

#endif
