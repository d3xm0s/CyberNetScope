// SPDX-License-Identifier: MIT
// cybernetscope - template-driven vulnerability scanner
// Scan engine: targets x templates over a worker pool, soft-404 calibration.

#include "cybernetscope/engine.hpp"

#include <condition_variable>
#include <mutex>
#include <memory>
#include <queue>
#include <random>
#include <thread>

namespace cybernetscope {

namespace {

// Shared rate limiter: a global minimum interval between request starts.
class RateLimiter {
public:
    explicit RateLimiter(int rps) {
        if (rps > 0) {
            interval_ = std::chrono::microseconds(1000000 / rps);
        }
    }

    void wait() {
        if (interval_.count() == 0) {
            return;
        }
        std::unique_lock<std::mutex> lock(mtx_);
        auto now = std::chrono::steady_clock::now();
        if (now < next_) {
            std::this_thread::sleep_until(next_);
            now = std::chrono::steady_clock::now();
        }
        next_ = now + interval_;
    }

private:
    std::chrono::microseconds interval_{0};
    std::mutex mtx_;
    std::chrono::steady_clock::time_point next_{};
};

// Minimal worker pool, same shape as the one used across the other tools.
class Pool {
public:
    explicit Pool(std::size_t workers) {
        if (workers == 0) {
            workers = 1;
        }
        for (std::size_t i = 0; i < workers; ++i) {
            threads_.emplace_back([this] { work(); });
        }
    }

    ~Pool() {
        {
            std::lock_guard<std::mutex> lock(mtx_);
            stop_ = true;
        }
        cv_.notify_all();
        for (auto& t : threads_) {
            if (t.joinable()) {
                t.join();
            }
        }
    }

    void push(std::function<void()> task) {
        {
            std::lock_guard<std::mutex> lock(mtx_);
            queue_.push(std::move(task));
        }
        cv_.notify_one();
    }

private:
    void work() {
        while (true) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lock(mtx_);
                cv_.wait(lock, [this] { return stop_ || !queue_.empty(); });
                if (stop_ && queue_.empty()) {
                    return;
                }
                task = std::move(queue_.front());
                queue_.pop();
            }
            task();
        }
    }

    std::vector<std::thread> threads_;
    std::queue<std::function<void()>> queue_;
    std::mutex mtx_;
    std::condition_variable cv_;
    bool stop_ = false;
};

std::string random_path() {
    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution<int> hex(0, 15);
    std::string p = "/cybernetscope-cal-";
    for (int i = 0; i < 8; ++i) {
        p += "0123456789abcdef"[static_cast<std::size_t>(hex(rng))];
    }
    return p;
}

// Normalize a target into a base URL. Bare hosts get probed: https first,
// then http when the handshake or connect fails.
http::Url base_url(const std::string& target, const EngineOptions& opts) {
    http::Url url;
    if (!http::parse_url(target, url)) {
        return {};
    }
    if (!url.scheme.empty()) {
        return url;
    }

    http::Url https = url;
    https.scheme = "https";
    https.port = 443;
    http::Request probe;
    probe.url = https;
    probe.follow_redirects = false;
    probe.headers["User-Agent"] = opts.user_agent;
    if (http::send(probe, opts.timeout).ok) {
        return https;
    }

    http::Url plain = url;
    plain.scheme = "http";
    plain.port = 80;
    return plain;
}

// Fetch the baseline: a path that cannot exist. Templates that also match
// this response are matching a soft-404, not a real finding.
http::Response calibrate(const http::Url& base, const EngineOptions& opts,
                         RateLimiter& limiter) {
    http::Request req;
    req.url = base;
    req.url.path = random_path();
    req.follow_redirects = false;
    req.headers["User-Agent"] = opts.user_agent;
    limiter.wait();
    return http::send(req, opts.timeout);
}

std::string snippet(const std::string& body, std::size_t max = 160) {
    std::string out;
    out.reserve(max);
    for (char c : body) {
        if (out.size() >= max) {
            break;
        }
        out += (c == '\n' || c == '\r' || c == '\t') ? ' ' : c;
    }
    if (body.size() > max) {
        out += "...";
    }
    return out;
}

}  // namespace

std::vector<Finding> run_engine(const std::vector<std::string>& targets,
                                std::vector<Template>& templates,
                                const EngineOptions& opts) {
    std::vector<Finding> findings;
    std::mutex findings_mtx;
    RateLimiter limiter(opts.rate_limit);

    // Per-target state must outlive the worker tasks: heap-allocate it and
    // let the lambdas hold a shared_ptr copy.
    struct TargetCtx {
        http::Url base;
        std::string base_str;
        http::Response baseline;
        bool have_baseline = false;
    };
    std::vector<std::shared_ptr<TargetCtx>> ctxs;

    Pool pool(opts.threads);
    std::atomic<std::size_t> in_flight{0};

    for (const auto& target : targets) {
        http::Url base = base_url(target, opts);
        if (base.host.empty()) {
            continue;
        }
        auto ctx = std::make_shared<TargetCtx>();
        ctx->base = base;
        ctx->base_str = base.scheme + "://" + base.host +
            ((base.scheme == "http" && base.port != 80) ||
             (base.scheme == "https" && base.port != 443)
                 ? ":" + std::to_string(base.port) : "");

        // One calibration hit per target, up front, before the pool fans out.
        if (opts.calibrate) {
            ctx->baseline = calibrate(base, opts, limiter);
            ctx->have_baseline = ctx->baseline.ok;
        }
        ctxs.push_back(ctx);

        for (auto& tmpl : templates) {
            for (auto& spec : tmpl.requests) {
                in_flight.fetch_add(1);
                pool.push([&, ctx, &tmpl = tmpl, &spec = spec] {
                    struct Guard {
                        std::atomic<std::size_t>& c;
                        ~Guard() { c.fetch_sub(1); }
                    } guard{in_flight};

                    for (const auto& path : spec.paths) {
                        http::Request req;
                        req.method = spec.method;
                        req.url = ctx->base;
                        req.url.path = path;
                        req.body = spec.body;
                        req.follow_redirects = spec.follow_redirects;
                        req.headers["User-Agent"] = opts.user_agent;
                        for (const auto& [k, v] : spec.headers) {
                            req.headers[k] = v;
                        }

                        limiter.wait();
                        http::Response resp = http::send(req, opts.timeout);
                        if (!resp.ok) {
                            break;  // dead target: no point trying more paths
                        }

                        RequestSpec eval = spec;  // local copy: regex cache
                        if (!eval_matchers(eval, resp)) {
                            continue;
                        }

                        // The same matchers firing on the calibration response
                        // means we caught a soft-404, not the real thing.
                        if (ctx->have_baseline && eval_matchers(eval, ctx->baseline)) {
                            continue;
                        }

                        Finding f;
                        f.target = ctx->base_str;
                        f.matched_url = resp.final_url.empty()
                            ? ctx->base_str + path : resp.final_url;
                        f.tmpl = &tmpl;
                        f.evidence = run_extractors(eval, resp);
                        f.response_snippet = snippet(resp.body);

                        if (opts.on_finding) {
                            opts.on_finding(f);
                        }
                        {
                            std::lock_guard<std::mutex> lock(findings_mtx);
                            findings.push_back(std::move(f));
                        }
                        break;  // first matching path wins for this request
                    }
                });
            }
        }
    }

    // Drain: wait until every queued task reports done, otherwise the return
    // would copy the findings vector while workers still append to it.
    while (in_flight.load() != 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return findings;
}

}  // namespace cybernetscope
