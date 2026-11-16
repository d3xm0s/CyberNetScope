// SPDX-License-Identifier: MIT
// cybernetscope - template-driven vulnerability scanner
// Finding output: console, JSON, SARIF.

#pragma once

#include <ostream>
#include <vector>

#include "cybernetscope/engine.hpp"

namespace cybernetscope {

// Streaming console line for one finding: [id] [severity] url evidence.
void print_finding_console(const Finding& f, std::ostream& os, bool color);

void print_summary(const std::vector<Finding>& findings, std::ostream& os,
                   bool color);

void write_json(const std::vector<Finding>& findings, std::ostream& os);

// SARIF 2.1.0, digestible by GitHub code scanning and most SAST dashboards.
void write_sarif(const std::vector<Finding>& findings, std::ostream& os);

}  // namespace cybernetscope
