// SPDX-License-Identifier: MIT
// cybernetscope - template-driven vulnerability scanner
// Command-line entry point.

#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "cybernetscope/engine.hpp"
#include "cybernetscope/report.hpp"
#include "cybernetscope/template.hpp"

namespace {

constexpr const char* kVersion = "0.1.0";

const char* kBanner = R"(
   ___      _              _  _     _   ___
  / __|  _ | |__  ___ _ _ | \| |___| |_/ __| __ ___ _ __  ___
 | (_| || || '_ \/ -_) '_|| .` / -_)  _\__ \/ _/ _ \ '_ \/ -_)
  \___\_, |_.__/\___|_|  |_|\_\___|\__|___/\__\___/ .__/\___|
      |__/                d3xm0s                  |_|
)";

struct Args {
    std::vector<std::string> urls;
    std::string targets_file;
    std::string templates_dir = "templates";
    std::set<std::string> tags;
    std::set<std::string> exclude_tags;
    std::set<std::string> severities;
    cybernetscope::EngineOptions engine;
    std::string json_out;
    std::string sarif_out;
    std::string grep_out;
    bool no_color = false;
    bool quiet = false;
};

void usage(const char* prog) {
    std::cout <<
        "cybernetscope " << kVersion << " - template-driven vulnerability scanner\n\n"
        "Usage:\n"
        "  " << prog << " -u <url> [options]\n\n"
        "Targets:\n"
        "  -u, --url URL        target URL or host (repeatable)\n"
        "  -iL, --input FILE    read targets from FILE, one per line\n\n"
        "Templates:\n"
        "  -t, --templates DIR  template directory (default: ./templates)\n"
        "      --tags A,B       only run templates with these tags\n"
        "      --exclude-tags A,B  skip templates with these tags\n"
        "      --severity S,S   only run these severities (info,low,medium,high,critical)\n\n"
        "Engine:\n"
        "  --threads N          concurrent workers (default: 50)\n"
        "  --timeout MS         per-request timeout (default: 8000)\n"
        "  --rate RPS           global request rate limit, 0 = unlimited (default: 0)\n"
        "  --no-calibrate       skip the soft-404 baseline check\n\n"
        "Output:\n"
        "  -j, --json FILE      write findings as JSON\n"
        "      --sarif FILE     write findings as SARIF 2.1.0\n"
        "  -oG, --grepable FILE write grepable lines (- for stdout)\n"
        "      --no-color       disable colored output\n"
        "  -q, --quiet          findings only, no banner or chatter\n"
        "  -h, --help           show this help\n"
        "  -v, --version        show version\n";
}

std::set<std::string> split_csv(const std::string& s) {
    std::set<std::string> out;
    std::size_t pos = 0;
    while (pos <= s.size()) {
        std::size_t comma = s.find(',', pos);
        std::string tok = s.substr(pos, comma - pos);
        if (!tok.empty()) {
            out.insert(tok);
        }
        if (comma == std::string::npos) {
            break;
        }
        pos = comma + 1;
    }
    return out;
}

bool parse_args(int argc, char** argv, Args& args) {
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](const char* name) -> std::string {
            if (i + 1 >= argc) {
                std::cerr << "error: " << name << " requires a value\n";
                std::exit(2);
            }
            return argv[++i];
        };

        if (a == "-h" || a == "--help") {
            usage(argv[0]);
            std::exit(0);
        } else if (a == "-v" || a == "--version") {
            std::cout << "cybernetscope " << kVersion << "\n";
            std::exit(0);
        } else if (a == "-u" || a == "--url") {
            args.urls.push_back(next("--url"));
        } else if (a == "-iL" || a == "--input") {
            args.targets_file = next("--input");
        } else if (a == "-t" || a == "--templates") {
            args.templates_dir = next("--templates");
        } else if (a == "--tags") {
            args.tags = split_csv(next("--tags"));
        } else if (a == "--exclude-tags") {
            args.exclude_tags = split_csv(next("--exclude-tags"));
        } else if (a == "--severity") {
            args.severities = split_csv(next("--severity"));
        } else if (a == "--threads") {
            args.engine.threads = static_cast<std::size_t>(std::stoul(next("--threads")));
        } else if (a == "--timeout") {
            args.engine.timeout = std::chrono::milliseconds(std::stoi(next("--timeout")));
        } else if (a == "--rate") {
            args.engine.rate_limit = std::stoi(next("--rate"));
        } else if (a == "--no-calibrate") {
            args.engine.calibrate = false;
        } else if (a == "-j" || a == "--json") {
            args.json_out = next("--json");
        } else if (a == "--sarif") {
            args.sarif_out = next("--sarif");
        } else if (a == "-oG" || a == "--grepable") {
            args.grep_out = next("--grepable");
        } else if (a == "--no-color") {
            args.no_color = true;
        } else if (a == "-q" || a == "--quiet") {
            args.quiet = true;
        } else {
            std::cerr << "error: unknown option " << a << "\n";
            return false;
        }
    }
    return true;
}

std::vector<std::string> load_targets(const std::string& path) {
    std::vector<std::string> out;
    std::ifstream in(path);
    std::string line;
    while (std::getline(in, line)) {
        std::size_t a = line.find_first_not_of(" \t\r\n");
        if (a == std::string::npos) {
            continue;
        }
        std::string t = line.substr(a, line.find_last_not_of(" \t\r\n") - a + 1);
        if (!t.empty() && t[0] != '#') {
            out.push_back(std::move(t));
        }
    }
    return out;
}

bool passes_filters(const cybernetscope::Template& t, const Args& args) {
    if (!args.severities.empty() &&
        args.severities.count(cybernetscope::severity_name(t.severity)) == 0) {
        return false;
    }
    if (!args.tags.empty()) {
        bool any = false;
        for (const auto& tag : t.tags) {
            if (args.tags.count(tag) != 0) {
                any = true;
                break;
            }
        }
        if (!any) {
            return false;
        }
    }
    for (const auto& tag : t.tags) {
        if (args.exclude_tags.count(tag) != 0) {
            return false;
        }
    }
    return true;
}

// Look next to the executable for installed templates when the default
// relative path is not there.
std::string installed_templates_dir(const char* argv0) {
    (void)argv0;
    char exe[4096] = {0};
    ssize_t n = ::readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n <= 0) {
        return {};
    }
    std::string dir(exe);
    std::size_t slash = dir.find_last_of('/');
    if (slash == std::string::npos) {
        return {};
    }
    return dir.substr(0, slash) + "/../share/cybernetscope/templates";
}

}  // namespace

int main(int argc, char** argv) {
    Args args;
    if (!parse_args(argc, argv, args)) {
        return 2;
    }

    bool color = !args.no_color && isatty(STDOUT_FILENO) && !args.quiet;
    if (!args.quiet) {
        if (color) {
            std::cout << "\033[1m\033[91m" << kBanner << "\033[0m\n";
        } else {
            std::cout << kBanner << "\n";
        }
    }

    if (!args.targets_file.empty()) {
        auto from_file = load_targets(args.targets_file);
        if (from_file.empty()) {
            std::cerr << "[!] target file '" << args.targets_file
                      << "' is empty or missing\n";
            return 2;
        }
        args.urls.insert(args.urls.end(), from_file.begin(), from_file.end());
    }

    if (args.urls.empty()) {
        usage(argv[0]);
        return 2;
    }

    // Template discovery: the given dir, then the installed share dir.
    std::vector<std::pair<std::string, std::string>> errors;
    auto templates = cybernetscope::load_templates_dir(args.templates_dir, errors);
    if (templates.empty()) {
        std::string installed = installed_templates_dir(argv[0]);
        if (!installed.empty()) {
            errors.clear();
            templates = cybernetscope::load_templates_dir(installed, errors);
        }
    }
    for (const auto& [path, err] : errors) {
        std::cerr << "[!] " << path << ": " << err << "\n";
    }
    if (templates.empty()) {
        std::cerr << "[!] no templates found in " << args.templates_dir << "\n";
        return 2;
    }

    std::vector<cybernetscope::Template> active;
    for (auto& t : templates) {
        if (passes_filters(t, args)) {
            active.push_back(std::move(t));
        }
    }
    if (active.empty()) {
        std::cerr << "[!] filters excluded every template\n";
        return 2;
    }

    if (!args.quiet) {
        std::cerr << "[*] " << args.urls.size() << " target(s), "
                  << active.size() << " template(s)\n";
    }

    std::mutex out_mtx;
    args.engine.on_finding = [&](const cybernetscope::Finding& f) {
        std::lock_guard<std::mutex> lock(out_mtx);
        cybernetscope::print_finding_console(f, std::cout, color);
        std::cout.flush();
    };

    auto findings = cybernetscope::run_engine(args.urls, active, args.engine);

    // Callback already printed each finding; the summary closes the run.
    if (!args.quiet) {
        cybernetscope::print_summary(findings, std::cout, color);
    }

    if (!args.json_out.empty()) {
        std::ofstream out(args.json_out);
        if (!out) {
            std::cerr << "[!] cannot write JSON to " << args.json_out << "\n";
            return 1;
        }
        cybernetscope::write_json(findings, out);
        if (!args.quiet) {
            std::cerr << "[+] JSON written to " << args.json_out << "\n";
        }
    }

    if (!args.sarif_out.empty()) {
        std::ofstream out(args.sarif_out);
        if (!out) {
            std::cerr << "[!] cannot write SARIF to " << args.sarif_out << "\n";
            return 1;
        }
        cybernetscope::write_sarif(findings, out);
        if (!args.quiet) {
            std::cerr << "[+] SARIF written to " << args.sarif_out << "\n";
        }
    }

    if (!args.grep_out.empty()) {
        std::ostream* os = &std::cout;
        std::ofstream file;
        if (args.grep_out != "-") {
            file.open(args.grep_out);
            if (!file) {
                std::cerr << "[!] cannot write grepable output to "
                          << args.grep_out << "\n";
                return 1;
            }
            os = &file;
        }
        for (const auto& f : findings) {
            *os << f.target << " " << f.tmpl->id << " "
                << cybernetscope::severity_name(f.tmpl->severity) << " "
                << f.matched_url << "\n";
        }
    }

    return 0;
}
