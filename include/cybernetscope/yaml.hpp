// SPDX-License-Identifier: MIT
// cybernetscope - template-driven vulnerability scanner
// Minimal YAML subset parser for the template format.

#pragma once

#include <string>
#include <utility>
#include <vector>

namespace cybernetscope {

// Ordered YAML node: scalar, map, or list. Only what the template format
// needs - indentation-based maps and lists, quoted scalars, inline [a, b]
// lists. Block scalars and anchors are deliberately not supported.
struct YamlValue {
    std::string scalar;
    std::vector<std::pair<std::string, YamlValue>> map;
    std::vector<YamlValue> list;

    bool is_map() const { return !map.empty(); }
    bool is_list() const { return !list.empty(); }
    bool is_scalar() const { return map.empty() && list.empty(); }

    // Look up a key in a map node. Returns nullptr if absent or not a map.
    const YamlValue* find(const std::string& key) const;

    // Scalar as string, or "" for non-scalars.
    std::string str() const { return is_scalar() ? scalar : std::string{}; }

    // Scalar list as strings; a scalar node becomes a one-element list.
    std::vector<std::string> str_list() const;
};

// Parse a document. Returns false with `error` set on malformed input.
bool parse_yaml(const std::string& text, YamlValue& root, std::string& error);

}  // namespace cybernetscope
