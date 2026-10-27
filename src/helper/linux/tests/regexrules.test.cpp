// Unit tests for the regex app-rule matching policy (regex_matching.h).  A regex entry admits a
// process when the pattern partial-matches the resolved exe path, or — only when the exe is a
// wine host binary — any raw argv token.  These cases pin the partial-match semantics, the wine
// gate, and the dead-rule behavior.  No external test framework; returns the number of failed
// checks (0 on success).

#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include <re2/re2.h>

#include "../split_tunneling/regex_matching.h"

namespace
{

int g_failures = 0;

bool check(bool ok, const char *expr, int line)
{
    if (!ok) {
        ++g_failures;
        printf("FAIL (line %d): %s\n", line, expr);
    }
    return ok;
}

#define VERIFY(expr) check(!!(expr), #expr, __LINE__)

std::unique_ptr<RE2> compile(const std::string &pattern)
{
    RE2::Options options;
    options.set_log_errors(false);
    return std::unique_ptr<RE2>(new RE2(pattern, options));
}

} // namespace

int main()
{
    const std::string winePreloader = "/mnt/big/SteamLibrary/steamapps/common/Proton 9.0/files/bin/wine64-preloader";
    const std::string steamScript = "/usr/bin/steam";
    const std::vector<std::string> wineArgv = {
        "S:\\common\\Deadlock\\game\\bin\\win64\\deadlock.exe",
        "-steam"
    };

    // Partial-match semantics: an unanchored pattern hits anywhere in the path.
    {
        const auto re = compile("steam");
        VERIFY(re->ok());
        VERIFY(regex_matching::regexRuleMatches(*re, steamScript, nullptr, false));
        VERIFY(regex_matching::regexRuleMatches(*re, winePreloader, nullptr, false));
        VERIFY(!regex_matching::regexRuleMatches(*re, "/usr/bin/firefox", nullptr, false));
    }

    // Anchored patterns behave like full-path rules.
    {
        const auto re = compile("^/usr/bin/firefox$");
        VERIFY(re->ok());
        VERIFY(regex_matching::regexRuleMatches(*re, "/usr/bin/firefox", nullptr, false));
        VERIFY(!regex_matching::regexRuleMatches(*re, "/usr/bin/firefox-esr", nullptr, false));
    }

    // Case-insensitive flag works (Windows path semantics users expect from wine rules).
    {
        RE2::Options options;
        options.set_log_errors(false);
        options.set_case_sensitive(false);
        const RE2 re("deadlock\\.exe", options);
        VERIFY(re.ok());
        VERIFY(RE2::PartialMatch(wineArgv[0], re));
    }

    // argv matching is gated on the wine-host exe: a wine path pattern must NOT classify a
    // non-wine process merely because a token mentions the path (editor/grep scenario).
    {
        const auto re = compile("deadlock\\.exe");
        VERIFY(re->ok());
        VERIFY(regex_matching::regexRuleMatches(*re, winePreloader, &wineArgv, /*exeLooksLikeWineHost=*/true));
        VERIFY(!regex_matching::regexRuleMatches(*re, "/usr/bin/gedit", &wineArgv, /*exeLooksLikeWineHost=*/false));
        // ... and the exe path itself is always fair game regardless of the gate.
        VERIFY(regex_matching::regexRuleMatches(*re, "/games/Deadlock/deadlock.exe", nullptr, false));
    }

    // Same gate for script-style tokens: argv carries the script path while the interpreter runs.
    {
        const auto re = compile("^/usr/bin/steam$");
        VERIFY(re->ok());
        const std::vector<std::string> bashArgv = { "/bin/bash", "/usr/lib/steam/steam" };
        VERIFY(!regex_matching::regexRuleMatches(*re, "/usr/bin/bash", &bashArgv, /*exeLooksLikeWineHost=*/false));
    }

    // A wine-host exe with NO argv is matched on exe alone.
    {
        const auto re = compile("preloader");
        VERIFY(re->ok());
        VERIFY(regex_matching::regexRuleMatches(*re, winePreloader, nullptr, true));
    }

    // Compiles-rejected (dead) patterns never match anything.
    {
        const auto re = compile("([unclosed");
        VERIFY(!re->ok());
        VERIFY(!regex_matching::regexRuleMatches(*re, steamScript, nullptr, false));
    }

    // Catastrophic-pattern safety: RE2 compiles nested quantifiers that would destroy a
    // backtracking engine and matches them in linear time — this is why the helper uses RE2
    // rather than std::regex for user-supplied patterns.
    {
        const auto re = compile("(a+)+$");
        VERIFY(re->ok());
        std::string pathological(64, 'a');
        pathological += 'X';
        VERIFY(!regex_matching::regexRuleMatches(*re, pathological, nullptr, false));
    }

    if (g_failures == 0) {
        printf("regexrules.test: all checks passed\n");
        return 0;
    }
    printf("regexrules.test: %d check(s) FAILED\n", g_failures);
    return 1;
}
