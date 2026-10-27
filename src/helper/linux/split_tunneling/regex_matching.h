#pragma once

// Pure regex-rule matching policy for the split-tunneling process monitor. Split out from
// process_monitor.cpp so the semantics are unit-testable without the monitor's netlink sockets
// (tests/regexrules.test.cpp); the only dependency is RE2, whose linear-time guarantee is what
// makes user-supplied patterns safe to execute in the privileged helper.

#include <string>
#include <vector>

#include <re2/re2.h>

namespace regex_matching {

// True when a regex app rule admits the process: the pattern partial-matches the resolved
// /proc/<pid>/exe path, or — under the same wine-host gate the path rules use (exeLooksLikeWineHost)
// — any raw argv token. Partial-match semantics: a pattern is "matched anywhere in the string", the
// usable default for path patterns ("steam" matches /usr/bin/steam and a SteamLibrary tree alike);
// users anchor explicitly (^/opt/games/.*). argv matching is intentionally gated on the exe being a
// wine host binary so a pattern that merely appears as a data argument (editor, grep) cannot
// classify an unrelated process.
inline bool regexRuleMatches(const RE2 &pattern, const std::string &exe,
                             const std::vector<std::string> *argv, bool exeLooksLikeWineHost)
{
    if (!pattern.ok()) {
        return false;
    }
    if (!exe.empty() && RE2::PartialMatch(exe, pattern)) {
        return true;
    }
    if (argv && exeLooksLikeWineHost) {
        for (const std::string &token : *argv) {
            if (RE2::PartialMatch(token, pattern)) {
                return true;
            }
        }
    }
    return false;
}

} // namespace regex_matching
