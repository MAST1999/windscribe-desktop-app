#pragma once

#include <atomic>
#include <string>
#include <mutex>
#include <vector>
#include "cgroups.h"
#include "hostnames_manager/hostnames_manager.h"
#include "process_monitor.h"
#include "../routes_manager/routes.h"
#include "../routes_manager/routes_manager.h"
#include "../../common/helper_commands.h"

class SplitTunneling
{
public:
    static SplitTunneling& instance()
    {
        static SplitTunneling st;
        return st;
    }

    bool setConnectParams(ConnectStatus &connectStatus);
    void setSplitTunnelingParams(bool isActive, bool isExclude, const std::vector<std::string> &apps,
                                 const std::vector<std::string> &ips, const std::vector<std::string> &hosts, bool isAllowLanTraffic);

    // V2 intake (setSplitTunnelingSettingsV2): the V1 fields plus the regex/country rule kinds and
    // the user-provided GeoIP database path. The V1 fields follow the exact setSplitTunnelingParams
    // flow; the new kinds are stored for their enforcement layers (ProcessMonitor for process
    // regexes, FirewallController + CountryRangesLoader for countries) and the GeoIP file is
    // (re)parsed on a worker thread — never on the IPC thread.
    void setSplitTunnelingParamsV2(bool isActive, bool isExclude, bool isAllowLanTraffic,
                                   const std::vector<std::string> &apps,
                                   const std::vector<std::string> &ips, const std::vector<std::string> &hosts,
                                   const std::vector<std::string> &regexProcessRules,
                                   const std::vector<std::string> &regexDomainRules,
                                   const std::vector<std::string> &countryCodes,
                                   const std::string &geoipDatabasePath);

private:
    std::mutex mutex_;

    ConnectStatus connectStatus_;

    bool isSplitTunnelActive_;
    bool isExclude_;
    bool isAllowLanTraffic_;

    HostnamesManager hostnamesManager_;
    RoutesManager routesManager_;

    std::vector<std::string> apps_;

    // New-rule-kind state (V2). regexDomainRules_ is carried for the DNS-layer phase; the GeoIP
    // path feeds CountryRangesLoader, whose parsed ranges the FirewallController consumes.
    std::vector<std::string> regexProcessRules_;
    std::vector<std::string> regexDomainRules_;
    std::vector<std::string> countries_;
    std::string geoipPath_;
    // Guards the detached GeoIP parse worker so consecutive V2 commands don't stack parses; the
    // worker loops until the current path is up-to-date, so a command arriving mid-parse is
    // absorbed by the running worker instead.
    std::atomic<bool> geoipParseBusy_{false};

    // Worker body: parses the current GeoIP path (looping if it changes mid-run) and re-applies the
    // firewall so freshly parsed ranges (or an emptied selection) reach the kernel.
    void geoipParseWorker();

    SplitTunneling();
    ~SplitTunneling();
    bool updateState();
};
