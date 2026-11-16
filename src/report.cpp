// SPDX-License-Identifier: MIT
// cybernetscope - template-driven vulnerability scanner
// Finding output: console, JSON, SARIF.

#include "cybernetscope/report.hpp"

#include <algorithm>
#include <cstdio>

namespace cybernetscope {

namespace {

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

const char* severity_color(Severity s, bool color) {
    if (!color) {
        return "";
    }
    switch (s) {
        case Severity::Critical: return "\033[1m\033[91m";  // bold red
        case Severity::High: return "\033[91m";
        case Severity::Medium: return "\033[93m";
        case Severity::Low: return "\033[96m";
        default: return "\033[2m";
    }
}

// SARIF levels only know error/warning/note.
const char* sarif_level(Severity s) {
    if (s == Severity::Critical || s == Severity::High) return "error";
    if (s == Severity::Medium) return "warning";
    return "note";
}

}  // namespace

void print_finding_console(const Finding& f, std::ostream& os, bool color) {
    const char* sc = severity_color(f.tmpl->severity, color);
    const char* reset = color ? "\033[0m" : "";
    os << "[" << f.tmpl->id << "] " << sc << "[" << severity_name(f.tmpl->severity)
       << "]" << reset << " " << f.matched_url;
    if (!f.evidence.empty()) {
        os << "  (";
        for (std::size_t i = 0; i < f.evidence.size(); ++i) {
            if (i > 0) {
                os << ", ";
            }
            os << f.evidence[i];
            if (os.tellp() > 400) {  // keep one line readable
                os << "...";
                break;
            }
        }
        os << ")";
    }
    os << "\n";
}

void print_summary(const std::vector<Finding>& findings, std::ostream& os,
                   bool color) {
    int counts[6] = {0};
    for (const auto& f : findings) {
        int r = severity_rank(f.tmpl->severity);
        if (r >= 0 && r < 6) {
            ++counts[r];
        }
    }
    os << "\n[+] " << findings.size() << " verified finding(s)";
    if (!findings.empty()) {
        os << ":";
        if (counts[5]) os << (color ? "\033[1m\033[91m" : "") << " " << counts[5] << " critical" << (color ? "\033[0m" : "");
        if (counts[4]) os << (color ? "\033[91m" : "") << " " << counts[4] << " high" << (color ? "\033[0m" : "");
        if (counts[3]) os << (color ? "\033[93m" : "") << " " << counts[3] << " medium" << (color ? "\033[0m" : "");
        if (counts[2]) os << " " << counts[2] << " low";
        if (counts[1]) os << " " << counts[1] << " info";
    }
    os << "\n";
}

void write_json(const std::vector<Finding>& findings, std::ostream& os) {
    os << "{\n  \"findings\": [\n";
    for (std::size_t i = 0; i < findings.size(); ++i) {
        const auto& f = findings[i];
        os << "    {\n";
        os << "      \"id\": \"" << json_escape(f.tmpl->id) << "\",\n";
        os << "      \"name\": \"" << json_escape(f.tmpl->name) << "\",\n";
        os << "      \"severity\": \"" << severity_name(f.tmpl->severity) << "\",\n";
        os << "      \"target\": \"" << json_escape(f.target) << "\",\n";
        os << "      \"matched_url\": \"" << json_escape(f.matched_url) << "\",\n";
        os << "      \"tags\": [";
        for (std::size_t t = 0; t < f.tmpl->tags.size(); ++t) {
            os << "\"" << json_escape(f.tmpl->tags[t]) << "\"";
            if (t + 1 < f.tmpl->tags.size()) os << ", ";
        }
        os << "],\n";
        os << "      \"evidence\": [";
        for (std::size_t e = 0; e < f.evidence.size(); ++e) {
            os << "\"" << json_escape(f.evidence[e]) << "\"";
            if (e + 1 < f.evidence.size()) os << ", ";
        }
        os << "],\n";
        os << "      \"reference\": \"" << json_escape(f.tmpl->reference) << "\",\n";
        os << "      \"snippet\": \"" << json_escape(f.response_snippet) << "\"\n";
        os << "    }";
        if (i + 1 < findings.size()) os << ",";
        os << "\n";
    }
    os << "  ]\n}\n";
}

void write_sarif(const std::vector<Finding>& findings, std::ostream& os) {
    // One rule per template id, one result per finding.
    std::vector<std::string> rule_ids;
    for (const auto& f : findings) {
        if (std::find(rule_ids.begin(), rule_ids.end(), f.tmpl->id) == rule_ids.end()) {
            rule_ids.push_back(f.tmpl->id);
        }
    }

    os << "{\n"
          "  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n"
          "  \"version\": \"2.1.0\",\n"
          "  \"runs\": [{\n"
          "    \"tool\": {\"driver\": {\"name\": \"cybernetscope\", "
          "\"informationUri\": \"https://github.com/d3xm0s/cybernetscope\",\n"
          "      \"rules\": [\n";

    bool first_rule = true;
    for (const auto& id : rule_ids) {
        const Finding* sample = nullptr;
        for (const auto& f : findings) {
            if (f.tmpl->id == id) {
                sample = &f;
                break;
            }
        }
        if (!first_rule) os << ",\n";
        first_rule = false;
        os << "        {\"id\": \"" << json_escape(id) << "\", "
           << "\"name\": \"" << json_escape(sample->tmpl->name) << "\", "
           << "\"shortDescription\": {\"text\": \""
           << json_escape(sample->tmpl->name) << "\"}, "
           << "\"properties\": {\"severity\": \""
           << severity_name(sample->tmpl->severity) << "\"}}";
    }

    os << "\n      ]}},\n    \"results\": [\n";
    for (std::size_t i = 0; i < findings.size(); ++i) {
        const auto& f = findings[i];
        os << "      {\"ruleId\": \"" << json_escape(f.tmpl->id) << "\", "
           << "\"level\": \"" << sarif_level(f.tmpl->severity) << "\", "
           << "\"message\": {\"text\": \""
           << json_escape(f.tmpl->name + " at " + f.matched_url) << "\"}, "
           << "\"locations\": [{\"physicalLocation\": {\"artifactLocation\": "
           << "{\"uri\": \"" << json_escape(f.matched_url) << "\"}}}]}";
        if (i + 1 < findings.size()) os << ",";
        os << "\n";
    }
    os << "    ]\n  }]\n}\n";
}

}  // namespace cybernetscope
