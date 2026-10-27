#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <re2/re2.h>

#include "types/ipaddress.h"

// DNS-layer classifier for split-tunneling domain-regex rules (docs/plans/
// split-tunneling-regex-and-country.md §5.4-A). A minimal forward-and-inspect UDP proxy bound to
// 127.0.0.1: an nft redirect (installed by FirewallController only while domain-regex rules are
// active) sends locally generated udp/53 queries here; the resolver
//   1. reads the question name,
//   2. matches it against the user's RE2 patterns (partial-match, like sing-box domain_regex),
//   3. forwards the query UNMODIFIED to the tunnel's DNS server and relays the answer back —
//      it never fabricates DNS data, so a resolver bug can only cost latency, not resolution,
//   4. for matched queries, extracts the answer's A/AAAA records and reports them so the
//      FirewallController can program the bypass set for those destinations.
//
// TCP/53 and DoH/DoT traffic is not redirected (documented v1 limitation).
class DomainRegexResolver
{
public:
    static DomainRegexResolver &instance()
    {
        static DomainRegexResolver r;
        return r;
    }

    // Port the local proxy binds; the nft redirect targets this port.
    static constexpr uint16_t kListenPort = 15353;
    static constexpr const char *kListenAddress = "127.0.0.1";

    // Replaces the pattern set (RE2-compiled here; invalid patterns are logged and dropped).
    void setPatterns(const std::vector<std::string> &patterns);
    // Tunnel DNS servers to forward to (first usable v4 wins; empty = feature inert).
    void setUpstreams(const std::vector<std::string> &servers);
    // Starts/stops the proxy thread. enable() is a no-op without patterns or an upstream, so a
    // resolver problem can never hijack system DNS when the feature is not in use.
    void enable();
    void disable();
    bool isEnabled() const { return running_; }

    // Called (from the resolver thread) with the answer IPs of matched queries.
    void setMatchedIpsHandler(std::function<void(const std::vector<types::IpAddressRange> &)> handler)
    {
        std::lock_guard<std::mutex> guard(handlerMutex_);
        handler_ = std::move(handler);
    }

    // First usable IPv4 upstream (empty when none), for the FirewallController's redirect
    // exclusion rule. Guarded by the same mutex as the upstream list.
    std::string upstreamV4() const;

    // For tests/diagnostics: match one name against the current patterns.
    bool matches(const std::string &qname) const;

private:
    DomainRegexResolver() = default;

    void worker();
    bool openSockets();
    void closeSockets();

    mutable std::mutex mutex_;
    std::vector<std::shared_ptr<const RE2>> patterns_;
    std::string upstream_;     // IPv4 literal of the DNS server we forward to

    std::atomic<bool> running_{false};
    std::thread thread_;
    int querySock_ = -1;       // bound to 127.0.0.1:kListenPort
    int upstreamSock_ = -1;    // connected to upstream_:53

    std::mutex handlerMutex_;
    std::function<void(const std::vector<types::IpAddressRange> &)> handler_;
};
