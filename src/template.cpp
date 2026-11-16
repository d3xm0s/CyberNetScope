// SPDX-License-Identifier: MIT
// cybernetscope - template-driven vulnerability scanner
// Template model, loader, and matcher evaluation.

#include "cybernetscope/template.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "cybernetscope/yaml.hpp"

namespace cybernetscope {

Severity severity_from_string(const std::string& s) {
    std::string low;
    low.reserve(s.size());
    for (char c : s) {
        low += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    if (low == "info") return Severity::Info;
    if (low == "low") return Severity::Low;
    if (low == "medium") return Severity::Medium;
    if (low == "high") return Severity::High;
    if (low == "critical") return Severity::Critical;
    return Severity::Unknown;
}

std::string severity_name(Severity s) {
    switch (s) {
        case Severity::Info: return "info";
        case Severity::Low: return "low";
        case Severity::Medium: return "medium";
        case Severity::High: return "high";
        case Severity::Critical: return "critical";
        default: return "unknown";
    }
}

int severity_rank(Severity s) {
    return static_cast<int>(s);
}

namespace {

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}

std::string get_str(const YamlValue& node, const std::string& key,
                    const std::string& fallback = "") {
    const YamlValue* v = node.find(key);
    return (v != nullptr) ? v->str() : fallback;
}

std::vector<std::string> get_list(const YamlValue& node, const std::string& key) {
    const YamlValue* v = node.find(key);
    return (v != nullptr) ? v->str_list() : std::vector<std::string>{};
}

bool get_bool(const YamlValue& node, const std::string& key, bool fallback) {
    std::string v = to_lower(get_str(node, key, ""));
    if (v == "true" || v == "yes" || v == "1") return true;
    if (v == "false" || v == "no" || v == "0") return false;
    return fallback;
}

Matcher parse_matcher(const YamlValue& node) {
    Matcher m;
    m.type = to_lower(get_str(node, "type", "word"));
    m.part = to_lower(get_str(node, "part", "body"));
    m.words = get_list(node, "words");
    m.regexes = get_list(node, "regex");
    m.hex = get_list(node, "binary");
    m.condition = to_lower(get_str(node, "condition", "or"));
    m.negative = get_bool(node, "negative", false);
    for (const auto& s : get_list(node, "status")) {
        m.statuses.push_back(std::atoi(s.c_str()));
    }
    return m;
}

Extractor parse_extractor(const YamlValue& node) {
    Extractor e;
    e.part = to_lower(get_str(node, "part", "body"));
    e.regexes = get_list(node, "regex");
    e.group = std::atoi(get_str(node, "group", "0").c_str());
    return e;
}

bool parse_template(const YamlValue& root, Template& out, std::string& error) {
    out.id = get_str(root, "id");
    if (out.id.empty()) {
        error = "missing id";
        return false;
    }

    const YamlValue* info = root.find("info");
    if (info == nullptr) {
        error = "missing info block";
        return false;
    }
    out.name = get_str(*info, "name");
    out.severity = severity_from_string(get_str(*info, "severity", "info"));
    out.description = get_str(*info, "description");
    out.reference = get_str(*info, "reference");
    out.tags = get_list(*info, "tags");
    if (out.name.empty()) {
        error = "missing info.name";
        return false;
    }

    const YamlValue* requests = root.find("requests");
    if (requests == nullptr || !requests->is_list()) {
        error = "missing requests list";
        return false;
    }

    for (const auto& rnode : requests->list) {
        RequestSpec r;
        r.method = get_str(rnode, "method", "GET");
        r.paths = get_list(rnode, "path");
        r.body = get_str(rnode, "body");
        r.follow_redirects = get_bool(rnode, "redirects", true);
        r.matchers_condition = to_lower(get_str(rnode, "matchers-condition", "and"));

        const YamlValue* headers = rnode.find("headers");
        if (headers != nullptr && headers->is_map()) {
            for (const auto& [k, v] : headers->map) {
                r.headers[k] = v.str();
            }
        }

        const YamlValue* matchers = rnode.find("matchers");
        if (matchers != nullptr && matchers->is_list()) {
            for (const auto& m : matchers->list) {
                r.matchers.push_back(parse_matcher(m));
            }
        }
        const YamlValue* extractors = rnode.find("extractors");
        if (extractors != nullptr && extractors->is_list()) {
            for (const auto& e : extractors->list) {
                r.extractors.push_back(parse_extractor(e));
            }
        }

        if (r.paths.empty()) {
            error = "request without path in template " + out.id;
            return false;
        }
        if (r.matchers.empty()) {
            error = "request without matchers in template " + out.id;
            return false;
        }
        out.requests.push_back(std::move(r));
    }
    return true;
}

// Pick the response slice a matcher/extractor works on.
std::string select_part(const http::Response& resp, const std::string& part) {
    if (part == "header") {
        return resp.raw_headers;
    }
    if (part == "raw") {
        return resp.raw_headers + "\r\n\r\n" + resp.body;
    }
    return resp.body;
}

std::vector<unsigned char> unhex(const std::string& h) {
    std::vector<unsigned char> out;
    for (std::size_t i = 0; i + 1 < h.size(); i += 2) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = nib(h[i]);
        int lo = nib(h[i + 1]);
        if (hi < 0 || lo < 0) {
            return {};
        }
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return out;
}

// std::regex (ECMAScript) has no inline flags: translate a leading (?i) into
// the icase flag, and drop patterns that fail to compile instead of letting
// one bad template kill the run.
void compile_patterns(const std::vector<std::string>& patterns,
                      std::vector<std::regex>& out) {
    for (const auto& p : patterns) {
        try {
            if (p.rfind("(?i)", 0) == 0) {
                out.emplace_back(p.substr(4), std::regex::icase);
            } else {
                out.emplace_back(p);
            }
        } catch (const std::regex_error&) {
            // bad pattern: it simply never matches
        }
    }
}

bool contains_bytes(const std::string& hay, const std::vector<unsigned char>& needle) {
    if (needle.empty() || hay.size() < needle.size()) {
        return false;
    }
    return std::search(hay.begin(), hay.end(), needle.begin(), needle.end()) != hay.end();
}

bool any_all(const std::vector<bool>& hits, const std::string& condition) {
    if (hits.empty()) {
        return false;
    }
    if (condition == "and") {
        return std::all_of(hits.begin(), hits.end(), [](bool h) { return h; });
    }
    return std::any_of(hits.begin(), hits.end(), [](bool h) { return h; });
}

}  // namespace

bool load_template(const std::string& path, Template& out, std::string& error) {
    std::ifstream in(path);
    if (!in) {
        error = "cannot read file";
        return false;
    }
    std::stringstream ss;
    ss << in.rdbuf();

    YamlValue root;
    if (!parse_yaml(ss.str(), root, error)) {
        error = "yaml: " + error;
        return false;
    }
    if (!parse_template(root, out, error)) {
        return false;
    }
    out.source_path = path;
    return true;
}

std::vector<Template> load_templates_dir(
    const std::string& dir,
    std::vector<std::pair<std::string, std::string>>& errors) {
    std::vector<Template> out;
    std::error_code ec;
    if (!std::filesystem::exists(dir, ec)) {
        errors.emplace_back(dir, "template directory not found");
        return out;
    }

    std::vector<std::string> files;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(dir, ec)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        std::string ext = entry.path().extension().string();
        if (ext == ".yaml" || ext == ".yml") {
            files.push_back(entry.path().string());
        }
    }
    std::sort(files.begin(), files.end());

    for (const auto& f : files) {
        Template t;
        std::string error;
        if (load_template(f, t, error)) {
            out.push_back(std::move(t));
        } else {
            errors.emplace_back(f, error);
        }
    }
    return out;
}

bool eval_matcher(Matcher& m, const http::Response& resp) {
    bool hit;
    if (m.type == "status") {
        hit = std::find(m.statuses.begin(), m.statuses.end(), resp.status) !=
              m.statuses.end();
    } else {
        std::string part = select_part(resp, m.part);
        std::vector<bool> hits;
        if (m.type == "regex") {
            if (m.compiled.empty()) {
                compile_patterns(m.regexes, m.compiled);
            }
            for (const auto& re : m.compiled) {
                hits.push_back(std::regex_search(part, re));
            }
        } else if (m.type == "binary") {
            for (const auto& h : m.hex) {
                hits.push_back(contains_bytes(part, unhex(h)));
            }
        } else {  // word
            for (const auto& w : m.words) {
                hits.push_back(part.find(w) != std::string::npos);
            }
        }
        hit = any_all(hits, m.condition);
    }
    return m.negative ? !hit : hit;
}

bool eval_matchers(RequestSpec& req, const http::Response& resp) {
    std::vector<bool> hits;
    for (auto& m : req.matchers) {
        hits.push_back(eval_matcher(m, resp));
    }
    return any_all(hits, req.matchers_condition);
}

std::vector<std::string> run_extractors(RequestSpec& req,
                                        const http::Response& resp) {
    std::vector<std::string> out;
    for (auto& e : req.extractors) {
        if (e.compiled.empty()) {
            compile_patterns(e.regexes, e.compiled);
        }
        std::string part = select_part(resp, e.part);
        for (const auto& re : e.compiled) {
            std::smatch m;
            if (std::regex_search(part, m, re)) {
                std::size_t g = (e.group >= 0 &&
                                 e.group < static_cast<int>(m.size()))
                                    ? static_cast<std::size_t>(e.group) : 0;
                out.push_back(m[g].str());
            }
        }
    }
    return out;
}

}  // namespace cybernetscope
