// Unit tests for CountryRangesLoader, the GeoIP index behind split-tunneling country
// pass-through (docs/plans/split-tunneling-regex-and-country.md).  Exercises the pure
// parse/merge helpers directly and the file parsers through temporary CSV fixtures
// covering both supported formats (DB-IP LITE and the GeoLite2-Country CSV set).
// No external test framework; returns the number of failed checks (0 on success).

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <sys/stat.h>

#include "../split_tunneling/country_ranges_loader.h"

using Range4 = CountryRangesLoader::Range4;
using Range6 = CountryRangesLoader::Range6;

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

bool writeFile(const std::string &path, const std::string &contents)
{
    FILE *f = fopen(path.c_str(), "wb");
    if (!f) {
        return false;
    }
    const bool ok = fwrite(contents.data(), 1, contents.size(), f) == contents.size();
    fclose(f);
    return ok;
}

bool touches(const std::vector<Range4> &ranges, uint32_t ip)
{
    for (const Range4 &r : ranges) {
        if (ip >= r.from && ip <= r.to) {
            return true;
        }
    }
    return false;
}

} // namespace

int main()
{
    // ---- pure helpers: v4 parsing ------------------------------------------------------------
    uint32_t ip = 0;
    VERIFY(CountryRangesLoader::parseIp4("1.2.3.4", ip) && ip == 0x01020304u);
    VERIFY(CountryRangesLoader::parseIp4("255.255.255.255", ip) && ip == 0xFFFFFFFFu);
    VERIFY(!CountryRangesLoader::parseIp4("256.1.1.1", ip));
    VERIFY(!CountryRangesLoader::parseIp4("1.2.3", ip));
    VERIFY(!CountryRangesLoader::parseIp4("not-an-ip", ip));
    VERIFY(!CountryRangesLoader::parseIp4("1.2.3.4/32", ip));       // bare literals only
    VERIFY(!CountryRangesLoader::parseIp4("::1", ip));

    // ---- pure helpers: v4 CIDR -> inclusive range --------------------------------------------
    Range4 r4;
    VERIFY(CountryRangesLoader::parseCidr4("10.0.0.0/8", r4) && r4.from == 0x0A000000u && r4.to == 0x0AFFFFFFu);
    VERIFY(CountryRangesLoader::parseCidr4("192.168.1.77/24", r4) && r4.from == 0xC0A80100u && r4.to == 0xC0A801FFu);
    VERIFY(CountryRangesLoader::parseCidr4("1.2.3.4/32", r4) && r4.from == r4.to && r4.from == 0x01020304u);
    VERIFY(CountryRangesLoader::parseCidr4("0.0.0.0/0", r4) && r4.from == 0 && r4.to == 0xFFFFFFFFu);
    VERIFY(!CountryRangesLoader::parseCidr4("1.2.3.4/33", r4));
    VERIFY(!CountryRangesLoader::parseCidr4("1.2.3.4", r4));        // CIDR suffix required

    // ---- pure helpers: v6 parsing ------------------------------------------------------------
    uint8_t a6[16];
    VERIFY(CountryRangesLoader::parseIp6("::", a6));
    VERIFY(CountryRangesLoader::parseIp6("2001:db8::1", a6) && a6[0] == 0x20 && a6[15] == 0x01);
    VERIFY(!CountryRangesLoader::parseIp6("1.2.3.4", a6));
    VERIFY(!CountryRangesLoader::parseIp6("2001:db8::z", a6));

    // ---- pure helpers: v6 CIDR -> inclusive range --------------------------------------------
    Range6 r6;
    VERIFY(CountryRangesLoader::parseCidr6("2001:db8::/32", r6));
    VERIFY(r6.from[0] == 0x20 && r6.from[3] == 0xB8);
    // range top must be 2001:db8:ffff:...:ffff
    bool allFF = true;
    for (int i = 4; i < 16; ++i) {
        allFF = allFF && r6.to[i] == 0xFF;
    }
    VERIFY(allFF && r6.to[0] == 0x20 && r6.to[3] == 0xB8);
    VERIFY(CountryRangesLoader::parseCidr6("::1/128", r6) && r6.from[15] == 1 && r6.to[15] == 1);
    VERIFY(CountryRangesLoader::parseCidr6("::/0", r6));
    bool allZero = true, allOne = true;
    for (int i = 0; i < 16; ++i) {
        allZero = allZero && r6.from[i] == 0;
        allOne = allOne && r6.to[i] == 0xFF;
    }
    VERIFY(allZero && allOne);
    VERIFY(!CountryRangesLoader::parseCidr6("2001:db8::/129", r6));

    // ---- pure helpers: merging (overlap, adjacency, containment, duplicates) ------------------
    std::vector<Range4> v4 = {
        { 100, 200 },
        { 10, 20 },          // before, disjoint
        { 21, 30 },          // adjacent to {10,20}
        { 150, 160 },        // contained
        { 200, 250 },        // overlapping + adjacent
        { 10, 20 },          // duplicate
        { 500, 501 },        // separate island (gap of 249 after 250)
        { 1000, 2000 },      // another gap keeps this separate
    };
    CountryRangesLoader::mergeRanges4(v4);
    VERIFY(v4.size() == 4);
    VERIFY(v4[0].from == 10 && v4[0].to == 30);       // {10,20}+{21,30} adjacent; duplicate absorbed
    VERIFY(v4[1].from == 100 && v4[1].to == 250);     // {100,200}+{150,160}+{200,250}
    VERIFY(v4[2].from == 500 && v4[2].to == 501);

    // Wraparound edge: merging adjacent into a full range must not overflow.
    std::vector<Range4> edge = { { 0, 0x7FFFFFFFu }, { 0x80000000u, 0xFFFFFFFFu } };
    CountryRangesLoader::mergeRanges4(edge);
    VERIFY(edge.size() == 1 && edge[0].from == 0 && edge[0].to == 0xFFFFFFFFu);

    // v6 adjacency across a byte boundary.
    Range6 hi, lo;
    VERIFY(CountryRangesLoader::parseCidr6("2001:db8::/32", lo));
    VERIFY(CountryRangesLoader::parseCidr6("2001:db9::/32", hi));   // adjacent at 32 bits
    std::vector<Range6> v6 = { hi, lo };
    CountryRangesLoader::mergeRanges6(v6);
    VERIFY(v6.size() == 1 && v6[0].from[3] == 0xB8);

    // ---- file parsing: DB-IP LITE format ------------------------------------------------------
    const std::string dbipPath = "/tmp/ws_test_dbip.csv";
    VERIFY(writeFile(dbipPath,
                     "ip_range_start,ip_range_end,country_code\n"
                     "1.0.0.0,1.0.0.255,AU\n"
                     "1.0.1.0,1.0.3.255,CN\n"
                     "1.0.4.0,1.0.7.255,AU\n"          // not adjacent to the CN block
                     "2a01:5c0::,2a01:5c0:ffff:ffff:ffff:ffff:ffff:ffff,DE\n"
                     "9.9.9.9,9.9.9.9,US\n"
                     "::ffff:8.8.8.0,::ffff:8.8.8.255,GB\n"   // v4-mapped v6: must land in the v4 index
                     "invalid,row,XX\n"                // skipped, not fatal
                     "5.5.5.5,5.5.5.5,\n"              // no country: skipped
                     ));
    {
        CountryRangesLoader &loader = CountryRangesLoader::instance();
        VERIFY(loader.ensureLoaded(dbipPath));
        VERIFY(loader.formatName() == "DB-IP LITE");
        VERIFY(loader.isUpToDate(dbipPath));

        const auto au = loader.ranges4("au");
        VERIFY(au.size() == 2);
        VERIFY(touches(au, 0x01000000u) && touches(au, 0x010000FFu) && touches(au, 0x01000400u) && touches(au, 0x010007FFu));
        VERIFY(!touches(au, 0x01000100u));   // the CN block must not leak into AU
        VERIFY(!touches(au, 0x01000800u));

        const auto cn = loader.ranges4("cn");
        VERIFY(cn.size() == 1 && touches(cn, 0x01000100u) && touches(cn, 0x010003FFu));

        const auto de = loader.ranges6("de");
        VERIFY(de.size() == 1 && de[0].from[0] == 0x2A && de[0].to[2] == 0x05);

        // v4-mapped v6 rows classify v4 traffic.
        const auto gb = loader.ranges4("gb");
        VERIFY(gb.size() == 1 && touches(gb, 0x08080800u) && touches(gb, 0x080808FFu));

        // Malformed CIDR prefix (garbage, not digits) must be rejected, not parsed as /0.
        VERIFY(!CountryRangesLoader::parseCidr4("1.2.3.0/", r4));
        VERIFY(!CountryRangesLoader::parseCidr4("1.2.3.0/2x", r4));
        VERIFY(!CountryRangesLoader::parseCidr6("2001:db8::/x", r6));

        // union merging and unknown-country tolerance: AU and CN blocks are adjacent at the byte
        // boundary, so the union must collapse into ONE contiguous range (cross-country merge is
        // what keeps the nft interval set overlap-free).
        const auto both = loader.unionRanges4({ "au", "cn", "zz" });
        VERIFY(both.size() == 1);
        VERIFY(touches(both, 0x01000000u) && touches(both, 0x010007FFu));
        VERIFY(loader.unionRanges4({}).empty());
        // headerless variant (DB-IP also ships headerless rows in some versions)
        VERIFY(writeFile(dbipPath,
                         "1.0.0.0,1.0.0.255,AU\n"
                         "1.0.1.0,1.0.3.255,CN\n"));
        // mtime granularity can swallow quick rewrites; bump the size instead (guaranteed change)
        VERIFY(writeFile(dbipPath,
                         "1.0.0.0,1.0.0.255,AU\n"
                         "1.0.1.0,1.0.3.255,CN\n"
                         "\n"));
        VERIFY(loader.ensureLoaded(dbipPath));
        VERIFY(loader.unionRanges4({ "au" }).size() == 1);
        VERIFY(loader.unionRanges4({ "cn" }).size() == 1);
    }

    // ---- file parsing: GeoLite2 blocks + locations -------------------------------------------
    // Use the real file names: when the IPv4 Blocks file is selected, the loader discovers the
    // IPv6 sibling and the Locations CSV in the same directory.
    const std::string v4Blocks = "/tmp/GeoLite2-Country-Blocks-IPv4.csv";
    const std::string v6Blocks = "/tmp/GeoLite2-Country-Blocks-IPv6.csv";
    const std::string locations = "/tmp/GeoLite2-Country-Locations-en.csv";
    VERIFY(writeFile(v4Blocks,
                     "network,registered_country_geoname_id,represented_country_geoname_id,registered_country_geoname_id,is_anonymous_proxy,is_satellite_provider\n"
                     "1.0.0.0/24,2077456,0,0,0,0\n"      // AU
                     "1.0.1.0/24,1814991,0,0,0,0\n"      // CN
                     "2.16.0.0/16,,0,0,0,0\n"            // no geoname: skipped
                     ));
    VERIFY(writeFile(v6Blocks,
                     "network,registered_country_geoname_id,represented_country_geoname_id,registered_country_geoname_id,is_anonymous_proxy,is_satellite_provider\n"
                     "2a01:5c0::/32,2921044,0,0,0,0\n"   // DE
                     ));
    VERIFY(writeFile(locations,
                     "geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name,is_in_european_union\n"
                     "1814991,en,AS,Asia,CN,China,0\n"
                     "2077456,en,OC,Oceania,AU,Australia,0\n"
                     "2921044,en,EU,Europe,DE,Germany,1\n"
                     "6255146,en,AS,Asia,,\"Asia (general)\",0\n"   // continent row: no ISO, skipped
                     ));
    {
        CountryRangesLoader &loader = CountryRangesLoader::instance();
        VERIFY(loader.ensureLoaded(v4Blocks));
        VERIFY(loader.formatName() == "GeoLite2");
        // One selection loads both families (the v6 sibling was found next to the v4 file).
        VERIFY(loader.ranges4("au").size() == 1);
        VERIFY(loader.ranges4("cn").size() == 1);
        VERIFY(loader.ranges6("de").size() == 1);
        VERIFY(loader.ranges4("de").empty());

        // ---- invalidation: change the file and verify the index follows ----------------------
        VERIFY(writeFile(v4Blocks,
                         "network,registered_country_geoname_id,represented_country_geoname_id,registered_country_geoname_id,is_anonymous_proxy,is_satellite_provider\n"
                         "1.0.0.0/24,2077456,0,0,0,0\n"
                         "3.0.0.0/8,2077456,0,0,0,0\n"));
        VERIFY(loader.ensureLoaded(v4Blocks));
        VERIFY(loader.ranges4("au").size() == 2);

        // ---- failure handling: a corrupt re-parse must keep the previous good index ----------
        VERIFY(writeFile(v4Blocks, std::string("\0\0\1binary", 8)));
        VERIFY(!loader.ensureLoaded(v4Blocks));
        VERIFY(loader.ranges4("au").size() == 2);   // previous index retained
        VERIFY(loader.countries().size() == 2);     // au, de (cn was dropped by the rewrite above)
    }
    std::remove(v4Blocks.c_str());
    std::remove(v6Blocks.c_str());
    std::remove(locations.c_str());
    std::remove(dbipPath.c_str());

    if (g_failures == 0) {
        printf("countryranges.test: all checks passed\n");
        return 0;
    }
    printf("countryranges.test: %d check(s) FAILED\n", g_failures);
    return 1;
}
