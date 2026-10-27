#include "domain_regex_resolver.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <unordered_map>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <re2/re2.h>
#include <spdlog/spdlog.h>

#include "dns_parse.h"

namespace
{

// Per-query relay bookkeeping: DNS transaction id -> client address. Ids are 16 bits and clients
// reuse them, so this holds at most one in-flight query per id; a collision overwrites an older
// entry, which costs one client a retry — the same behavior a NATted home router exhibits.
constexpr size_t kMaxPending = 1024;

bool isUsableIpv4(const std::string &s)
{
    struct in_addr a = {};
    return inet_pton(AF_INET, s.c_str(), &a) == 1;
}

} // namespace

void DomainRegexResolver::setPatterns(const std::vector<std::string> &patterns)
{
    std::vector<std::shared_ptr<const RE2>> compiled;
    compiled.reserve(patterns.size());
    for (const std::string &pattern : patterns) {
        RE2::Options options;
        options.set_log_errors(false);
        auto re = std::make_shared<const RE2>(pattern, options);
        if (!re->ok()) {
            spdlog::warn("DomainRegexResolver: dropping uncompilable pattern \"{}\": {}", pattern, re->error());
            continue;
        }
        compiled.push_back(std::move(re));
    }
    std::lock_guard<std::mutex> guard(mutex_);
    patterns_ = std::move(compiled);
}

void DomainRegexResolver::setUpstreams(const std::vector<std::string> &servers)
{
    std::lock_guard<std::mutex> guard(mutex_);
    upstream_.clear();
    for (const std::string &server : servers) {
        if (isUsableIpv4(server)) {
            upstream_ = server;
            break;
        }
    }
}

std::string DomainRegexResolver::upstreamV4() const
{
    std::lock_guard<std::mutex> guard(mutex_);
    return upstream_;
}

bool DomainRegexResolver::matches(const std::string &qname) const
{
    std::lock_guard<std::mutex> guard(mutex_);
    for (const auto &re : patterns_) {
        if (re->ok() && RE2::PartialMatch(qname, *re)) {
            return true;
        }
    }
    return false;
}

void DomainRegexResolver::enable()
{
    {
        std::lock_guard<std::mutex> guard(mutex_);
        if (patterns_.empty() || upstream_.empty()) {
            return;   // feature inert: never hijack DNS without both halves
        }
    }
    if (running_) {
        return;
    }
    if (!openSockets()) {
        return;
    }
    running_ = true;
    thread_ = std::thread(&DomainRegexResolver::worker, this);
    spdlog::info("DomainRegexResolver: listening on {}:{}", kListenAddress, kListenPort);
}

void DomainRegexResolver::disable()
{
    if (!running_.exchange(false)) {
        return;
    }
    if (thread_.joinable()) {
        thread_.join();
    }
    closeSockets();
    spdlog::info("DomainRegexResolver: stopped");
}

bool DomainRegexResolver::openSockets()
{
    querySock_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    upstreamSock_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (querySock_ < 0 || upstreamSock_ < 0) {
        spdlog::error("DomainRegexResolver: socket() failed: {}", strerror(errno));
        closeSockets();
        return false;
    }

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(kListenPort);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(querySock_, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) != 0) {
        spdlog::error("DomainRegexResolver: bind({}:{}) failed: {}", kListenAddress, kListenPort, strerror(errno));
        closeSockets();
        return false;
    }

    {
        std::lock_guard<std::mutex> guard(mutex_);
        struct sockaddr_in up = {};
        up.sin_family = AF_INET;
        up.sin_port = htons(53);
        inet_pton(AF_INET, upstream_.c_str(), &up.sin_addr);
        if (::connect(upstreamSock_, reinterpret_cast<struct sockaddr *>(&up), sizeof(up)) != 0) {
            spdlog::error("DomainRegexResolver: connect to upstream {} failed: {}", upstream_, strerror(errno));
            closeSockets();
            return false;
        }
    }

    // Non-blocking for the poll loop.
    for (int fd : { querySock_, upstreamSock_ }) {
        const int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    return true;
}

void DomainRegexResolver::closeSockets()
{
    for (int *fd : { &querySock_, &upstreamSock_ }) {
        if (*fd >= 0) {
            ::close(*fd);
            *fd = -1;
        }
    }
}

void DomainRegexResolver::worker()
{
    // Pending client replies, keyed by the DNS transaction id.
    std::unordered_map<uint16_t, struct sockaddr_in> pending;
    // Ids whose query matched a pattern (the response's answer IPs then feed the handler).
    std::unordered_map<uint16_t, bool> matched;

    constexpr size_t kBufSize = 4096;
    std::vector<uint8_t> buf(kBufSize);

    while (running_) {
        struct pollfd fds[2] = {
            { querySock_, POLLIN, 0 },
            { upstreamSock_, POLLIN, 0 },
        };
        const int rc = ::poll(fds, 2, 500);
        if (rc <= 0) {
            continue;
        }

        // Query from the system -> match + forward upstream.
        if (fds[0].revents & POLLIN) {
            struct sockaddr_in client = {};
            socklen_t clientLen = sizeof(client);
            const ssize_t n = ::recvfrom(querySock_, buf.data(), buf.size(), 0,
                                         reinterpret_cast<struct sockaddr *>(&client), &clientLen);
            if (n <= 0) {
                continue;
            }
            const auto header = dns_parse::parseHeader(buf.data(), static_cast<size_t>(n));
            if (!header || header->qdcount == 0) {
                continue;
            }
            const auto qname = dns_parse::queryName(buf.data(), static_cast<size_t>(n));
            const bool isMatch = qname && matches(*qname);

            if (pending.size() >= kMaxPending) {
                pending.clear();
                matched.clear();
            }
            pending[header->id] = client;
            matched[header->id] = isMatch;
            if (isMatch && qname) {
                spdlog::info("DomainRegexResolver: \"{}\" matched a domain-regex rule", *qname);
            }

            const ssize_t sent = ::send(upstreamSock_, buf.data(), static_cast<size_t>(n), 0);
            if (sent < 0) {
                pending.erase(header->id);
                matched.erase(header->id);
            }
        }

        // Response from upstream -> extract + report matched IPs, relay to the client.
        if (fds[1].revents & POLLIN) {
            const ssize_t n = ::recv(upstreamSock_, buf.data(), buf.size(), 0);
            if (n <= 0) {
                continue;
            }
            const auto header = dns_parse::parseHeader(buf.data(), static_cast<size_t>(n));
            if (!header) {
                continue;
            }
            const auto pendingIt = pending.find(header->id);
            if (pendingIt == pending.end()) {
                continue;   // answer to a query we did not forward (or a timed-out entry)
            }
            const bool wasMatch = matched.count(header->id) != 0 && matched[header->id];
            if (wasMatch) {
                const auto addrs = dns_parse::answerAddresses(buf.data(), static_cast<size_t>(n));
                if (!addrs.empty()) {
                    std::vector<types::IpAddressRange> ranges = types::IpAddressRange::fromStrings(addrs);
                    ranges.erase(std::remove_if(ranges.begin(), ranges.end(),
                                                [](const types::IpAddressRange &r) { return !r.isValid(); }),
                                 ranges.end());
                    if (!ranges.empty()) {
                        std::function<void(const std::vector<types::IpAddressRange> &)> handler;
                        {
                            std::lock_guard<std::mutex> guard(handlerMutex_);
                            handler = handler_;
                        }
                        if (handler) {
                            handler(ranges);
                        }
                    }
                }
            }
            ::sendto(querySock_, buf.data(), static_cast<size_t>(n), 0,
                     reinterpret_cast<const struct sockaddr *>(&pendingIt->second), sizeof(pendingIt->second));
            pending.erase(pendingIt);
            matched.erase(header->id);
        }
    }
}
