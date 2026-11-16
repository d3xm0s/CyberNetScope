// SPDX-License-Identifier: MIT
// cybernetscope - template-driven vulnerability scanner
// HTTP client over raw sockets and OpenSSL.

#include "cybernetscope/http.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <memory>

namespace cybernetscope::http {

namespace {

constexpr std::size_t kMaxBody = 4 * 1024 * 1024;
constexpr int kMaxRedirects = 5;

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}

std::string trim(const std::string& s) {
    std::size_t a = s.find_first_not_of(" \t\r");
    if (a == std::string::npos) {
        return {};
    }
    return s.substr(a, s.find_last_not_of(" \t\r") - a + 1);
}

bool connect_host(const std::string& host, uint16_t port,
                  std::chrono::milliseconds timeout, int& fd_out) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) {
        return false;
    }

    int fd = -1;
    for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
        fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) {
            continue;
        }
        int flags = ::fcntl(fd, F_GETFL, 0);
        ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        int rc = ::connect(fd, p->ai_addr, p->ai_addrlen);
        if (rc != 0 && errno == EINPROGRESS) {
            pollfd pfd{};
            pfd.fd = fd;
            pfd.events = POLLOUT;
            rc = ::poll(&pfd, 1, static_cast<int>(timeout.count()));
            if (rc > 0) {
                int err = 0;
                socklen_t len = sizeof(err);
                if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0) {
                    break;  // connected
                }
            }
            rc = -1;
        }
        if (rc == 0) {
            break;  // instant connect
        }
        ::close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        return false;
    }

    // Back to blocking with hard timeouts on send/recv.
    int flags = ::fcntl(fd, F_GETFL, 0);
    ::fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    timeval tv{};
    tv.tv_sec = timeout.count() / 1000;
    tv.tv_usec = (timeout.count() % 1000) * 1000;
    if (tv.tv_sec == 0 && tv.tv_usec == 0) {
        tv.tv_usec = 1000;
    }
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    fd_out = fd;
    return true;
}

struct SslDeleter {
    void operator()(SSL* s) const { if (s) SSL_free(s); }
};
struct CtxDeleter {
    void operator()(SSL_CTX* c) const { if (c) SSL_CTX_free(c); }
};

// Transport wrapper so plain and TLS sockets share the read/write code below.
class Transport {
public:
    Transport(int fd, SSL* ssl) : fd_(fd), ssl_(ssl) {}

    bool write_all(const std::string& data) {
        std::size_t sent = 0;
        while (sent < data.size()) {
            int n;
            if (ssl_ != nullptr) {
                n = SSL_write(ssl_, data.data() + sent,
                              static_cast<int>(data.size() - sent));
            } else {
                n = static_cast<int>(::send(fd_, data.data() + sent,
                                            data.size() - sent, MSG_NOSIGNAL));
            }
            if (n <= 0) {
                return false;
            }
            sent += static_cast<std::size_t>(n);
        }
        return true;
    }

    // Read until EOF (we send Connection: close) or the body cap.
    std::string read_all() {
        std::string out;
        char buf[16384];
        while (out.size() < kMaxBody + 65536) {
            int n;
            if (ssl_ != nullptr) {
                n = SSL_read(ssl_, buf, sizeof(buf));
            } else {
                n = static_cast<int>(::recv(fd_, buf, sizeof(buf), 0));
            }
            if (n <= 0) {
                break;
            }
            out.append(buf, static_cast<std::size_t>(n));
        }
        return out;
    }

private:
    int fd_;
    SSL* ssl_;
};

Response exchange(const Request& req, std::chrono::milliseconds timeout) {
    Response resp;

    int fd = -1;
    if (!connect_host(req.url.host, req.url.port, timeout, fd)) {
        resp.error = "connect failed";
        return resp;
    }

    std::unique_ptr<SSL_CTX, CtxDeleter> ctx;
    std::unique_ptr<SSL, SslDeleter> ssl;
    SSL* ssl_raw = nullptr;
    if (req.url.scheme == "https") {
        ctx.reset(SSL_CTX_new(TLS_client_method()));
        if (!ctx) {
            ::close(fd);
            resp.error = "tls context failed";
            return resp;
        }
        // Scanner, not a browser: self-signed and expired certs are answers,
        // not errors.
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);
        ssl.reset(SSL_new(ctx.get()));
        if (!ssl) {
            ::close(fd);
            resp.error = "tls init failed";
            return resp;
        }
        SSL_set_fd(ssl.get(), fd);
        SSL_set_tlsext_host_name(ssl.get(), req.url.host.c_str());
        if (SSL_connect(ssl.get()) != 1) {
            ::close(fd);
            resp.error = "tls handshake failed";
            return resp;
        }
        ssl_raw = ssl.get();
    }

    Transport io(fd, ssl_raw);

    std::string req_text = req.method + " " + req.url.path + " HTTP/1.1\r\n";
    req_text += "Host: " + req.url.host;
    if ((req.url.scheme == "http" && req.url.port != 80) ||
        (req.url.scheme == "https" && req.url.port != 443)) {
        req_text += ":" + std::to_string(req.url.port);
    }
    req_text += "\r\n";
    bool have_cl = false;
    for (const auto& [k, v] : req.headers) {
        if (to_lower(k) == "content-length") {
            have_cl = true;
        }
        req_text += k + ": " + v + "\r\n";
    }
    if (!req.body.empty() && !have_cl) {
        req_text += "Content-Length: " + std::to_string(req.body.size()) + "\r\n";
    }
    req_text += "Connection: close\r\n\r\n";
    req_text += req.body;

    if (!io.write_all(req_text)) {
        if (ssl_raw != nullptr) SSL_shutdown(ssl_raw);
        ::close(fd);
        resp.error = "write failed";
        return resp;
    }

    std::string raw = io.read_all();
    if (ssl_raw != nullptr) SSL_shutdown(ssl_raw);
    ::close(fd);

    std::size_t split = raw.find("\r\n\r\n");
    if (split == std::string::npos) {
        resp.error = "malformed response";
        return resp;
    }

    std::string head = raw.substr(0, split);
    resp.raw_headers = head;
    std::string body = raw.substr(split + 4);

    std::size_t sp1 = head.find(' ');
    if (sp1 == std::string::npos) {
        resp.error = "malformed status line";
        return resp;
    }
    resp.status = std::atoi(head.c_str() + sp1 + 1);

    std::size_t pos = head.find("\r\n");
    while (pos != std::string::npos && pos + 2 < head.size()) {
        std::size_t eol = head.find("\r\n", pos + 2);
        if (eol == std::string::npos) {
            eol = head.size();
        }
        std::string line = head.substr(pos + 2, eol - pos - 2);
        std::size_t colon = line.find(':');
        if (colon != std::string::npos) {
            resp.headers[to_lower(trim(line.substr(0, colon)))] =
                trim(line.substr(colon + 1));
        }
        pos = eol;
    }

    // Chunked transfer: decode in place.
    auto te = resp.headers.find("transfer-encoding");
    if (te != resp.headers.end() && to_lower(te->second).find("chunked") != std::string::npos) {
        std::string decoded;
        std::size_t p = 0;
        while (p < body.size()) {
            std::size_t eol = body.find("\r\n", p);
            if (eol == std::string::npos) {
                break;
            }
            long chunk = std::strtol(body.substr(p, eol - p).c_str(), nullptr, 16);
            if (chunk <= 0) {
                break;
            }
            p = eol + 2;
            if (p + chunk > body.size()) {
                break;
            }
            decoded.append(body, p, static_cast<std::size_t>(chunk));
            p += static_cast<std::size_t>(chunk) + 2;
            if (decoded.size() > kMaxBody) {
                break;
            }
        }
        body = std::move(decoded);
    }

    if (body.size() > kMaxBody) {
        body.resize(kMaxBody);
    }
    resp.body = std::move(body);
    resp.ok = true;
    return resp;
}

std::string join_location(const Url& base, const std::string& location) {
    if (location.rfind("http://", 0) == 0 || location.rfind("https://", 0) == 0) {
        return location;
    }
    std::string origin = base.scheme + "://" + base.host;
    if ((base.scheme == "http" && base.port != 80) ||
        (base.scheme == "https" && base.port != 443)) {
        origin += ":" + std::to_string(base.port);
    }
    if (!location.empty() && location[0] == '/') {
        return origin + location;
    }
    // Relative to the current directory.
    std::string dir = base.path.substr(0, base.path.find_last_of('/') + 1);
    return origin + dir + location;
}

}  // namespace

bool parse_url(const std::string& raw, Url& out) {
    std::string s = raw;
    out = Url{};

    std::size_t scheme_end = s.find("://");
    if (scheme_end != std::string::npos) {
        out.scheme = to_lower(s.substr(0, scheme_end));
        if (out.scheme != "http" && out.scheme != "https") {
            return false;
        }
        s = s.substr(scheme_end + 3);
    }

    std::size_t slash = s.find('/');
    std::string authority = (slash == std::string::npos) ? s : s.substr(0, slash);
    out.path = (slash == std::string::npos) ? "/" : s.substr(slash);
    if (authority.empty()) {
        return false;
    }

    std::size_t colon = authority.rfind(':');
    if (colon != std::string::npos &&
        authority.find(':') == colon &&              // not an IPv6 literal
        authority.find(']') == std::string::npos) {
        int p = std::atoi(authority.c_str() + colon + 1);
        if (p <= 0 || p > 65535) {
            return false;
        }
        out.port = static_cast<uint16_t>(p);
        out.explicit_port = true;
        out.host = authority.substr(0, colon);
    } else {
        out.host = authority;
        out.port = 0;
    }
    if (out.host.empty()) {
        return false;
    }
    return true;
}

std::string render_url(const Url& url) {
    std::string out = url.scheme + "://" + url.host;
    if (url.explicit_port) {
        out += ":" + std::to_string(url.port);
    }
    return out + url.path;
}

Response send(const Request& req, std::chrono::milliseconds timeout) {
    Request cur = req;
    for (int hop = 0;; ++hop) {
        Url url = cur.url;
        if (url.port == 0) {
            url.port = (url.scheme == "https") ? 443 : 80;
        }
        cur.url = url;

        Response resp = exchange(cur, timeout);
        if (!resp.ok || !cur.follow_redirects || hop >= kMaxRedirects) {
            resp.final_url = render_url(url);
            return resp;
        }

        bool is_redirect = resp.status == 301 || resp.status == 302 ||
                           resp.status == 303 || resp.status == 307 ||
                           resp.status == 308;
        auto loc = resp.headers.find("location");
        if (!is_redirect || loc == resp.headers.end() || loc->second.empty()) {
            resp.final_url = render_url(url);
            return resp;
        }

        Url next;
        if (!parse_url(join_location(url, loc->second), next)) {
            resp.final_url = render_url(url);
            return resp;
        }
        if (next.scheme.empty()) {
            next.scheme = url.scheme;
        }
        if (next.port == 0 && next.host == url.host) {
            next.port = url.port;
            next.explicit_port = url.explicit_port;
        }
        cur.url = next;
        if (resp.status == 303) {
            cur.method = "GET";
            cur.body.clear();
        }
    }
}

}  // namespace cybernetscope::http
