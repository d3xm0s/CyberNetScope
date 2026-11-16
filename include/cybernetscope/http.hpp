// SPDX-License-Identifier: MIT
// cybernetscope - template-driven vulnerability scanner
// HTTP client over raw sockets and OpenSSL.

#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace cybernetscope::http {

struct Url {
    std::string scheme;  // "http" or "https"
    std::string host;
    uint16_t port = 0;
    std::string path = "/";  // path + query
    bool explicit_port = false;  // port came from the URL text, not a default
};

// Parse a URL. Accepts bare hosts (scheme guessed by caller), host:port,
// full URLs with path and query.
bool parse_url(const std::string& raw, Url& out);

struct Request {
    std::string method = "GET";
    Url url;
    std::map<std::string, std::string> headers;
    std::string body;
    bool follow_redirects = true;
};

struct Response {
    bool ok = false;            // false on network/TLS failure
    int status = 0;
    std::map<std::string, std::string> headers;  // lowercase keys
    std::string raw_headers;
    std::string body;
    std::string final_url;      // after redirects
    std::string error;          // set when ok == false
};

// Send a request. Redirects (301/302/303/307/308) are followed up to 5 times
// when follow_redirects is set. Bodies are capped at 4 MB.
Response send(const Request& req, std::chrono::milliseconds timeout);

}  // namespace cybernetscope::http
