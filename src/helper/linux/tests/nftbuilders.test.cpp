// Golden tests for the nft command-buffer builders (nftables/nftablescontroller.h) used by the
// split-tunneling country and domain-regex enforcement: set creation/teardown idioms and the
// batched element emission.  These strings go to the kernel as one transaction, so their exact
// shape matters.  No external test framework; returns the number of failed checks (0 on success).

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

#include "../nftables/nftablescontroller.h"

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

} // namespace

int main()
{
    // ensureSet: create-if-absent + flush, exactly one of each, in order. (The `add table`
    // prologue is the caller's job — applySplitTunnel prepends nft::addTable().)
    {
        const std::string s = nft::ensureSet("ws_countries", "type ipv4_addr; flags interval;");
        VERIFY(s == "add set inet windscribe ws_countries { type ipv4_addr; flags interval; }\n"
                    "flush set inet windscribe ws_countries\n");
    }

    // deleteSet: the add-then-delete idiom (an absent set is created just to be removed, so the
    // transaction can never fail on a missing object).
    {
        const std::string s = nft::deleteSet("ws_dyn_domains", "type ipv4_addr; flags interval;");
        VERIFY(s == "add set inet windscribe ws_dyn_domains { type ipv4_addr; flags interval; }\n"
                    "delete set inet windscribe ws_dyn_domains\n");
    }

    // setElements: all elements land in one statement below the batch size.
    {
        const std::string s = nft::setElements("ws_countries", { "1.0.0.0-1.0.0.255", "1.0.1.0-1.0.3.255" });
        VERIFY(s == "add element inet windscribe ws_countries { 1.0.0.0-1.0.0.255, 1.0.1.0-1.0.3.255 }\n");
    }

    // setElements: batching at 256 elements per statement, in order, no trailing separators.
    {
        std::vector<std::string> elems;
        for (int i = 0; i < 257; ++i) {
            elems.push_back(std::to_string(i));
        }
        const std::string s = nft::setElements("ws_dyn_domains", elems);
        const size_t statements = std::count(s.begin(), s.end(), '\n');
        VERIFY(statements == 2);
        VERIFY(s.rfind("add element inet windscribe ws_dyn_domains { ", 0) == 0);
        // First statement holds 256, second holds 1.
        VERIFY(s.find("255, 256") == std::string::npos);           // boundary fell between statements
        VERIFY(s.find(", 255 }\n") != std::string::npos);          // ...and 255 ends the first
        VERIFY(s.find("{ 256 }\n") != std::string::npos);          // ...and 256 starts the second
    }

    // setElements: empty input emits nothing (an empty country selection adds no statements).
    VERIFY(nft::setElements("ws_countries", {}).empty());

    if (g_failures == 0) {
        printf("nftbuilders.test: all checks passed\n");
        return 0;
    }
    printf("nftbuilders.test: %d check(s) FAILED\n", g_failures);
    return 1;
}
