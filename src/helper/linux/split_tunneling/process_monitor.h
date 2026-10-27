#pragma once

#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>
#include <sys/types.h>

#include <re2/re2.h>

class ProcessMonitor
{
public:
    static ProcessMonitor& instance()
    {
        static ProcessMonitor pm;
        return pm;
    }

    void setApps(const std::vector<std::string> &apps);
    // Regex-based app entries: patterns matched (RE2, partial-match semantics) against the
    // resolved /proc/<pid>/exe path and — gated on a wine host exe, like the path rules —
    // against argv tokens. Kept separate from the path entries so pattern strings never
    // collide with the path/Flatpak-ID matching heuristics.
    void setRegexApps(const std::vector<std::string> &patterns);
    bool enable();
    void disable();

private:
    // One client-supplied app entry preprocessed into the forms used for matching.
    struct AppRule
    {
        std::string raw;             // as supplied, minus trailing slashes (snap prefix/suffix and Flatpak ID matching use this); a regex entry's pattern
        std::string canonical;       // realpath()-resolved; the same form /proc/<pid>/exe reports
        std::string canonicalSlash;  // canonical + "/"; precomputed for directory prefix matching
        std::string rawSlash;        // raw + "/"; same, for the unresolved spelling
        std::string scriptInterpreter;  // canonical shebang interpreter; non-empty => script-wrapped launcher
        bool isDirectory = false;    // the stored path is a directory (a whole app/game install tree)
        bool isRegex = false;        // raw is an RE2 pattern, not a path
        // Compiled pattern for regex entries; null when the pattern was rejected (dead rule).
        // Shared_ptr keeps AppRule copyable (RE2 itself is neither copyable nor movable).
        std::shared_ptr<const RE2> pattern;
    };

    bool isEnabled_;
    std::vector<std::string> apps_;  // raw entries in client form (add/remove diff logic)
    std::vector<std::string> regexApps_;  // raw regex patterns (same diff logic, separate namespace)
    std::vector<AppRule> rules_;     // matching form of apps_ + regexApps_, maintained by the rules worker
    std::mutex appsMutex_;           // guards apps_/regexApps_/rules_ against the monitor and rules threads

    std::thread *thread_;
    int sock_;
    bool running_;

    // Rule construction touches the filesystem (realpath/stat on client-supplied paths), which
    // can block indefinitely on an unresponsive FUSE/SMB/NFS mount.  It therefore runs on a
    // dedicated worker thread, never on the netlink monitor or IPC command threads: setApps()
    // only swaps in the raw entry list and wakes the worker, which resolves, swaps in the new
    // rules, and rescans /proc so entries added while a game is already running take effect
    // without a relaunch.  The monitor thread keeps matching against the previous rules until
    // the swap lands.
    std::thread rulesThread_;
    std::mutex rulesMutex_;
    std::condition_variable rulesCv_;
    bool rulesWake_ = false;
    bool rulesStop_ = false;

    bool functional_;
    bool testing_;
    int idleTicks_ = 0;  // monitorWorker's 250 ms poll timeout counter (rules refresh cadence)

    ProcessMonitor();
    ~ProcessMonitor();
    static AppRule ruleFor(const std::string &app);
    static AppRule ruleForRegex(const std::string &pattern);
    static std::vector<pid_t> expandToDescendants(const std::vector<pid_t> &roots);

    void rulesWorker();
    void requestRulesRebuild();
    void scanAndAddAll();
    void removeAppsForEntry(const std::string &entry, const std::vector<AppRule> &rules);
    std::vector<pid_t> findPidsForRule(const AppRule &rule);
    std::string getCmdByPid(pid_t pid);
    std::optional<std::string> getFlatpakAppIdByPid(pid_t pid);

    void selfTest();
    bool prepareMonitoring();
    bool startMonitoring();
    void stopMonitoring();
    void monitorWorker(void *ctx);
    bool compareCmd(pid_t pid, const std::vector<AppRule> &rules);
};
