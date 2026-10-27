#include "split_tunneling.h"

#include <algorithm>
#include <atomic>
#include <thread>
#include <spdlog/spdlog.h>
#include "../firewallcontroller.h"
#include "../utils.h"
#include "country_ranges_loader.h"
#include "domain_regex_resolver.h"
#include "types/ipaddress.h"

SplitTunneling::SplitTunneling(): isSplitTunnelActive_(false), isExclude_(false), isAllowLanTraffic_(false)
{
    connectStatus_.isConnected = false;

    // Cause the process monitor to start.  We want this because the process monitor needs to perform a self-test
    ProcessMonitor::instance();
}

SplitTunneling::~SplitTunneling()
{
}

bool SplitTunneling::setConnectParams(ConnectStatus &connectStatus)
{
    std::lock_guard<std::mutex> guard(mutex_);
    spdlog::debug("isConnected: {}, protocol: {}", connectStatus.isConnected, (int)connectStatus.protocol);
    connectStatus_ = connectStatus;
    routesManager_.updateState(connectStatus_, isSplitTunnelActive_, isExclude_);
    return updateState();
}

void SplitTunneling::setSplitTunnelingParamsV2(bool isActive, bool isExclude, bool isAllowLanTraffic,
    const std::vector<std::string> &apps, const std::vector<std::string> &ips, const std::vector<std::string> &hosts,
    const std::vector<std::string> &regexProcessRules, const std::vector<std::string> &regexDomainRules,
    const std::vector<std::string> &countryCodes, const std::string &geoipDatabasePath)
{
    {
        std::lock_guard<std::mutex> guard(mutex_);
        regexProcessRules_ = regexProcessRules;
        regexDomainRules_ = regexDomainRules;
        countries_ = countryCodes;
        geoipPath_ = geoipDatabasePath;
    }

    // Domain-regex patterns feed the DNS-layer classifier (enforcement state is armed from
    // updateState() on connect, where the tunnel DNS upstreams become known).
    DomainRegexResolver::instance().setPatterns(regexDomainRules);
    // Push the (possibly emptied) selection to the firewall right away: the sets get rebuilt from
    // whatever ranges the loader currently holds — empty when the file is not parsed (yet), so a
    // half-ready state degrades to "no country rules", never to broken rules. The GeoIP parse
    // worker re-applies once ranges become available.
    FirewallController::instance().setSplitTunnelCountryRules(countryCodes);

    // Kick the (re)parse off the IPC thread. The worker loops until the CURRENT path/contents are
    // up-to-date, so a V2 command arriving mid-parse is absorbed without stacking workers.
    if (!geoipDatabasePath.empty() && !CountryRangesLoader::instance().isUpToDate(geoipDatabasePath)) {
        bool expected = false;
        if (geoipParseBusy_.compare_exchange_strong(expected, true)) {
            std::thread(&SplitTunneling::geoipParseWorker, this).detach();
        }
    }

    // Base fields follow the unchanged V1 flow (apps/ips/hosts -> monitor/routes/firewall), plus
    // the regex process rules for the monitor.
    ProcessMonitor::instance().setRegexApps(regexProcessRules);
    setSplitTunnelingParams(isActive, isExclude, apps, ips, hosts, isAllowLanTraffic);
}

// Arms or disarms the domain-regex DNS classifier from current connect + settings state.
// Caller MUST hold mutex_ (both updateState() call sites do): this reads regexDomainRules_ and
// connectStatus_ directly. The resolver/firewall take their own locks, so calling outward here is
// safe under mutex_.
void SplitTunneling::updateDomainRegexState()
{
    DomainRegexResolver &resolver = DomainRegexResolver::instance();

    std::string upstreamV4;
    std::string upstreamV6;
    bool wantActive = connectStatus_.isConnected && isSplitTunnelActive_ && isExclude_
                      && !regexDomainRules_.empty();
    for (const auto &dns : connectStatus_.vpnAdapter.dnsServers) {
        if (!dns.isValid()) {
            continue;
        }
        if (upstreamV4.empty() && !dns.isV6()) {
            upstreamV4 = dns.toString();
        }
        if (upstreamV6.empty() && dns.isV6()) {
            upstreamV6 = dns.toString();
        }
    }
    if (upstreamV4.empty() && upstreamV6.empty()) {
        wantActive = false;   // nowhere to forward: keep the feature inert rather than blackhole DNS
    }
    resolver.setUpstreams(upstreamV4.empty() ? std::vector<std::string>{} : std::vector<std::string>{upstreamV4});

    if (wantActive) {
        resolver.setMatchedIpsHandler([](const std::vector<types::IpAddressRange> &ranges) {
            FirewallController::instance().addDynamicDomainIps(ranges);
        });
        FirewallController::instance().setSplitTunnelDomainRegexState(true, upstreamV4, upstreamV6);
        resolver.enable();
    } else {
        resolver.disable();
        FirewallController::instance().setSplitTunnelDomainRegexState(false, std::string(), std::string());
    }
}

void SplitTunneling::geoipParseWorker()
{
    for (;;) {
        std::string path;
        {
            std::lock_guard<std::mutex> guard(mutex_);
            path = geoipPath_;
        }
        if (!path.empty() && !CountryRangesLoader::instance().isUpToDate(path)) {
            std::string err;
            if (!CountryRangesLoader::instance().ensureLoaded(path, &err)) {
                // The loader keeps its previous index on failure; re-apply anyway so the firewall
                // reflects a consistent (possibly stale/empty) country selection. A changed or
                // fixed file arrives via the next V2 command or (size, mtime) change.
                spdlog::warn("SplitTunneling: GeoIP database unusable ({}), country rules off until the file changes", err);
                FirewallController::instance().applySplitTunnel();
            } else {
                spdlog::info("SplitTunneling: GeoIP database loaded, re-applying country rules");
                FirewallController::instance().applySplitTunnel();
            }
        }

        // Release the busy flag, then RE-CHECK under the lock: a V2 command that arrived while we
        // were marked busy failed its compare-exchange (the spawn slot was taken) and relies on us
        // noticing its path here. Redundant workers are harmless — ensureLoaded() is idempotent
        // and mutex-protected — so a spawn that slips into the release window is fine.
        geoipParseBusy_ = false;
        std::lock_guard<std::mutex> guard(mutex_);
        const std::string fresh = geoipPath_;
        if (fresh.empty() || CountryRangesLoader::instance().isUpToDate(fresh)) {
            return;
        }
        geoipParseBusy_ = true;   // keep the slot and loop for the newly changed file
    }
}

void SplitTunneling::setSplitTunnelingParams(bool isActive, bool isExclude, const std::vector<std::string> &apps,
    const std::vector<std::string> &ips, const std::vector<std::string> &hosts, bool isAllowLanTraffic)
{
    std::lock_guard<std::mutex> guard(mutex_);
    apps_ = apps;

    spdlog::debug("isSplitTunnelingActive: {}, isExclude: {}, isAllowLanTraffic {}", isActive, isExclude, isAllowLanTraffic);

    isSplitTunnelActive_ = isActive;
    isExclude_ = isExclude;
    isAllowLanTraffic_ = isAllowLanTraffic;

    if (isActive && !isExclude) {
        apps_.push_back(WS_LINUX_INSTALL_DIR "/" WS_APP_EXECUTABLE_NAME);
    }

    // Convert raw user/ROBERT-supplied IP strings into typed dual-stack ranges so the
    // HostnamesManager / IpRoutes / FirewallController layers can dispatch by family.
    // Invalid entries are dropped here so they never reach the shell-command boundary.
    auto ipRanges = types::IpAddressRange::fromStrings(ips);
    ipRanges.erase(
        std::remove_if(ipRanges.begin(), ipRanges.end(),
                       [](const types::IpAddressRange &r) { return !r.isValid(); }),
        ipRanges.end());

    hostnamesManager_.setSettings(ipRanges, hosts);
    routesManager_.updateState(connectStatus_, isSplitTunnelActive_, isExclude_);
    ProcessMonitor::instance().setApps(apps_);
    updateState();
}


bool SplitTunneling::updateState()
{
    updateDomainRegexState();

    if (connectStatus_.isConnected && isSplitTunnelActive_) {
        if (!apps_.empty() || !regexProcessRules_.empty()) {
            bool ret = CGroups::instance().enable(connectStatus_, isAllowLanTraffic_, isExclude_);
            if (!ret) {
                return ret;
            }
            ret = ProcessMonitor::instance().enable();
            if (!ret) {
                return ret;
            }
        }

        if (isExclude_) {
            // Exclude mode: excluded destinations that the main table already routes around the
            // tunnel (e.g. a secondary LAN) are left alone; the rest, which would have used the
            // default route, are pinned via the default adapter.
            std::vector<std::string> tunnelDevs;
            for (const auto &dev : {connectStatus_.vpnAdapter.adapterName, connectStatus_.vpnAdapter.adapterNameV6}) {
                if (!dev.empty()) {
                    tunnelDevs.push_back(dev);
                }
            }
            hostnamesManager_.enable(connectStatus_.defaultAdapter.gatewayIp,
                                     connectStatus_.defaultAdapter.gatewayIpV6,
                                     connectStatus_.defaultAdapter.adapterIp,
                                     connectStatus_.defaultAdapter.adapterIpV6,
                                     connectStatus_.defaultAdapter.adapterName,
                                     connectStatus_.defaultAdapter.adapterNameV6,
                                     tunnelDevs);
        } else {
            // Inclusive mode: host pins for included apps route via the VPN adapter.
            // The adapter IPs are also forwarded so HostnamesManager/IpRoutes can
            // detect the WireGuard point-to-point case (gatewayIp == adapterIp,
            // see wireguardconnection_posix.cpp) and emit `dev <iface>` instead
            // of `via <our-own-addr>`, which the kernel rejects.
            hostnamesManager_.enable(connectStatus_.vpnAdapter.gatewayIp,
                                     connectStatus_.vpnAdapter.gatewayIpV6,
                                     connectStatus_.vpnAdapter.adapterIp,
                                     connectStatus_.vpnAdapter.adapterIpV6,
                                     connectStatus_.vpnAdapter.adapterName,
                                     connectStatus_.vpnAdapter.adapterNameV6,
                                     {});
        }
    } else {
        CGroups::instance().disable();
        ProcessMonitor::instance().disable();
        hostnamesManager_.disable();
    }

    // Pass both families' default-adapter addresses; the firewall layer dispatches the
    // ingress-connmark path per-family. adapterIpV6.toString() returns "" for an invalid
    // IpAddress (no v6 detected), which the firewall layer treats as "skip the v6 path".
    FirewallController::instance().setSplitTunnelingEnabled(
        connectStatus_.isConnected,
        isSplitTunnelActive_,
        isExclude_,
        connectStatus_.defaultAdapter.adapterName,
        connectStatus_.defaultAdapter.adapterIp.toString(),
        connectStatus_.defaultAdapter.adapterIpV6.toString());
    return true;
}
