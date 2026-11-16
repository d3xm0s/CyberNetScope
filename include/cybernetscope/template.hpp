// SPDX-License-Identifier: MIT
// cybernetscope - template-driven vulnerability scanner
// Template model, loader, and matcher evaluation.

#pragma once

#include <map>
#include <regex>
#include <string>
#include <vector>

#include "cybernetscope/http.hpp"

namespace cybernetscope {

enum class Severity { Unknown, Info, Low, Medium, High, Critical };

Severity severity_from_string(const std::string& s);
std::string severity_name(Severity s);
int severity_rank(Severity s);

struct Matcher {
    std::string type;              // status | word | regex | binary
    std::string part = "body";     // body | header | raw
    std::vector<std::string> words;
    std::vector<int> statuses;
    std::vector<std::string> regexes;
    std::vector<std::string> hex;  // binary patterns, hex strings
    std::string condition = "or";  // how the entries inside combine
    bool negative = false;

    mutable std::vector<std::regex> compiled;  // regex cache, built once
};

struct Extractor {
    std::string part = "body";
    std::vector<std::string> regexes;
    int group = 0;

    mutable std::vector<std::regex> compiled;
};

struct RequestSpec {
    std::string method = "GET";
    std::vector<std::string> paths;
    std::map<std::string, std::string> headers;
    std::string body;
    bool follow_redirects = true;
    std::vector<Matcher> matchers;
    std::string matchers_condition = "and";  // how the matchers combine
    std::vector<Extractor> extractors;
};

struct Template {
    std::string id;
    std::string name;
    Severity severity = Severity::Unknown;
    std::string description;
    std::string reference;
    std::vector<std::string> tags;
    std::vector<RequestSpec> requests;
    std::string source_path;
};

// Load one template file. Returns false with `error` set when the file is
// unreadable or structurally invalid (missing id/info/requests/matchers).
bool load_template(const std::string& path, Template& out, std::string& error);

// Recursively load every *.yaml / *.yml under dir. Bad files are skipped and
// reported through `errors` (path -> message) instead of aborting the run.
std::vector<Template> load_templates_dir(
    const std::string& dir,
    std::vector<std::pair<std::string, std::string>>& errors);

// Matcher evaluation against a response.
bool eval_matcher(Matcher& m, const http::Response& resp);
bool eval_matchers(RequestSpec& req, const http::Response& resp);

// Extractor pass: returns captured evidence strings.
std::vector<std::string> run_extractors(RequestSpec& req,
                                        const http::Response& resp);

}  // namespace cybernetscope
