// SPDX-License-Identifier: MIT
// cybernetscope - template-driven vulnerability scanner
// Minimal YAML subset parser for the template format.

#include "cybernetscope/yaml.hpp"

#include <cctype>

namespace cybernetscope {

const YamlValue* YamlValue::find(const std::string& key) const {
    for (const auto& [k, v] : map) {
        if (k == key) {
            return &v;
        }
    }
    return nullptr;
}

std::vector<std::string> YamlValue::str_list() const {
    std::vector<std::string> out;
    if (is_scalar()) {
        if (!scalar.empty()) {
            out.push_back(scalar);
        }
        return out;
    }
    for (const auto& item : list) {
        if (item.is_scalar()) {
            out.push_back(item.scalar);
        }
    }
    return out;
}

namespace {

struct Line {
    int indent;
    std::string text;  // trimmed, comments stripped
};

int indent_of(const std::string& s) {
    int n = 0;
    while (n < static_cast<int>(s.size()) && s[static_cast<std::size_t>(n)] == ' ') {
        ++n;
    }
    return n;
}

// Strip a trailing comment, respecting quotes so "a # b" survives.
std::string strip_comment(const std::string& s) {
    bool in_single = false;
    bool in_double = false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '\'' && !in_double) {
            in_single = !in_single;
        } else if (c == '"' && !in_single) {
            if (i == 0 || s[i - 1] != '\\') {
                in_double = !in_double;
            }
        } else if (c == '#' && !in_single && !in_double &&
                   (i == 0 || s[i - 1] == ' ' || s[i - 1] == '\t')) {
            return s.substr(0, i);
        }
    }
    return s;
}

std::string trim(const std::string& s) {
    std::size_t a = s.find_first_not_of(" \t\r");
    if (a == std::string::npos) {
        return {};
    }
    std::size_t b = s.find_last_not_of(" \t\r");
    return s.substr(a, b - a + 1);
}

std::string unquote(const std::string& s) {
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
        std::string out;
        for (std::size_t i = 1; i + 1 < s.size(); ++i) {
            if (s[i] == '\\' && i + 2 < s.size()) {
                switch (s[i + 1]) {
                    case 'n': out += '\n'; ++i; continue;
                    case 't': out += '\t'; ++i; continue;
                    case '"': out += '"'; ++i; continue;
                    case '\\': out += '\\'; ++i; continue;
                    default: break;
                }
            }
            out += s[i];
        }
        return out;
    }
    if (s.size() >= 2 && s.front() == '\'' && s.back() == '\'') {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

// Parse a scalar token: quoted string or inline [a, b] list.
YamlValue scalar_node(const std::string& tok) {
    YamlValue v;
    std::string t = trim(tok);
    if (t.size() >= 2 && t.front() == '[' && t.back() == ']') {
        std::string inner = trim(t.substr(1, t.size() - 2));
        std::size_t pos = 0;
        bool in_q = false;
        char qc = 0;
        std::string cur;
        auto flush = [&]() {
            YamlValue item;
            item.scalar = unquote(trim(cur));
            if (!item.scalar.empty()) {
                v.list.push_back(std::move(item));
            }
            cur.clear();
        };
        while (pos < inner.size()) {
            char c = inner[pos];
            if (in_q) {
                cur += c;
                if (c == qc && inner[pos - 1] != '\\') {
                    in_q = false;
                }
            } else if (c == '"' || c == '\'') {
                in_q = true;
                qc = c;
                cur += c;
            } else if (c == ',') {
                flush();
            } else {
                cur += c;
            }
            ++pos;
        }
        flush();
        return v;
    }
    v.scalar = unquote(t);
    return v;
}

class Parser {
public:
    explicit Parser(const std::string& text) {
        std::size_t pos = 0;
        while (pos <= text.size()) {
            std::size_t eol = text.find('\n', pos);
            if (eol == std::string::npos) {
                eol = text.size();
            }
            std::string raw = text.substr(pos, eol - pos);
            pos = eol + 1;
            std::string no_comment = strip_comment(raw);
            std::string t = trim(no_comment);
            if (t.empty() || t == "---" || t == "...") {
                continue;
            }
            lines_.push_back({indent_of(no_comment), t});
        }
    }

    bool parse(YamlValue& root, std::string& error) {
        std::size_t i = 0;
        if (lines_.empty()) {
            error = "empty document";
            return false;
        }
        bool ok = parse_block(root, i, lines_[0].indent, error);
        if (ok && i < lines_.size()) {
            error = "trailing content after document root";
            return false;
        }
        return ok;
    }

private:
    std::vector<Line> lines_;

    bool parse_block(YamlValue& out, std::size_t& i, int indent, std::string& error) {
        if (i >= lines_.size() || lines_[i].indent < indent) {
            return true;
        }
        // The block's real indent comes from its first line; callers only pass
        // a lower bound, and deeper-than-expected indentation is legal.
        int block_indent = lines_[i].indent;
        if (lines_[i].text.rfind("- ", 0) == 0 || lines_[i].text == "-") {
            return parse_list(out, i, block_indent, error);
        }
        return parse_map(out, i, block_indent, error);
    }

    bool parse_list(YamlValue& out, std::size_t& i, int indent, std::string& error) {
        while (i < lines_.size() && lines_[i].indent == indent &&
               (lines_[i].text.rfind("- ", 0) == 0 || lines_[i].text == "-")) {
            std::string item = trim(lines_[i].text.substr(1));
            ++i;

            if (item.empty()) {
                // Bare dash: the value sits on deeper lines.
                YamlValue child;
                if (!parse_block(child, i, indent + 1, error)) {
                    return false;
                }
                out.list.push_back(std::move(child));
                continue;
            }

            std::size_t colon = item.find(':');
            if (colon != std::string::npos &&
                (colon + 1 >= item.size() || item[colon + 1] == ' ')) {
                // "- key: value" starts a map; deeper lines at indent+2 or
                // more continue that same map.
                YamlValue node;
                std::string key = trim(item.substr(0, colon));
                std::string rest = trim(item.substr(colon + 1));
                if (!rest.empty()) {
                    node.map.emplace_back(key, scalar_node(rest));
                } else {
                    YamlValue child;
                    if (!parse_block(child, i, indent + 2, error)) {
                        return false;
                    }
                    node.map.emplace_back(key, std::move(child));
                }
                while (i < lines_.size() && lines_[i].indent > indent) {
                    if (lines_[i].text.rfind("- ", 0) == 0) {
                        break;  // deeper list items belong to a parsed child
                    }
                    std::string sub = lines_[i].text;
                    std::size_t sc = sub.find(':');
                    if (sc == std::string::npos) {
                        error = "expected key: value, got: " + sub;
                        return false;
                    }
                    int sub_indent = lines_[i].indent;
                    std::string skey = trim(sub.substr(0, sc));
                    std::string srest = trim(sub.substr(sc + 1));
                    ++i;
                    if (!srest.empty()) {
                        node.map.emplace_back(skey, scalar_node(srest));
                    } else {
                        YamlValue child;
                        if (!parse_block(child, i, sub_indent + 1, error)) {
                            return false;
                        }
                        node.map.emplace_back(skey, std::move(child));
                    }
                }
                out.list.push_back(std::move(node));
                continue;
            }

            out.list.push_back(scalar_node(item));
        }
        return true;
    }

    bool parse_map(YamlValue& out, std::size_t& i, int indent, std::string& error) {
        while (i < lines_.size() && lines_[i].indent == indent &&
               lines_[i].text.rfind("- ", 0) != 0) {
            std::string text = lines_[i].text;
            std::size_t colon = text.find(':');
            if (colon == std::string::npos) {
                error = "expected key: value, got: " + text;
                return false;
            }
            std::string key = trim(text.substr(0, colon));
            std::string rest = trim(text.substr(colon + 1));
            ++i;
            if (!rest.empty()) {
                out.map.emplace_back(key, scalar_node(rest));
            } else {
                YamlValue child;
                if (!parse_block(child, i, indent + 1, error)) {
                    return false;
                }
                out.map.emplace_back(key, std::move(child));
            }
        }
        return true;
    }
};

}  // namespace

bool parse_yaml(const std::string& text, YamlValue& root, std::string& error) {
    Parser p(text);
    return p.parse(root, error);
}

}  // namespace cybernetscope
