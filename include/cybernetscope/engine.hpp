// SPDX-License-Identifier: MIT
// cybernetscope - template-driven vulnerability scanner
// Scan engine: targets x templates over a worker pool, soft-404 calibration.

#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <string>
#include <vector>

#include "cybernetscope/http.hpp"
#include "cybernetscope/template.hpp"

namespace cybernetscope {

struct Finding {
    std::string target;                 // base URL that was scanned
    std::string matched_url;            // final URL after redirects
    const Template* tmpl;               // template that fired (owned by caller)
    std::vector<std::string> evidence;  // extractor output
    std::string response_snippet;       // first bytes of the matching body
};

struct EngineOptions {
    std::size_t threads = 50;
    std::chrono::milliseconds timeout{8000};
    int rate_limit = 0;        // requests per second, 0 = unlimited
    bool calibrate = true;     // soft-404 baseline per target
    std::string user_agent = "cybernetscope/0.1";
    std::function<void(const Finding&)> on_finding;  // streaming callback
};

// Run every template against every target. Returns the verified findings.
std::vector<Finding> run_engine(const std::vector<std::string>& targets,
                                std::vector<Template>& templates,
                                const EngineOptions& opts);

}  // namespace cybernetscope
