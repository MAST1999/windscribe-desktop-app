#pragma once

#include <cstdint>
#include <cstddef>
#include <map>
#include <mutex>
#include <string>
#include <vector>

// Parses a user-provided GeoIP database into per-country, pre-merged IPv4/IPv6 range indexes for
// the split-tunneling country pass-through feature (docs/plans/split-tunneling-regex-and-country.md).
// No GeoIP data ships with the app ("bring-your-own-database"): the user downloads a supported
// file and points the app at it; this class only READS it.
//
// Supported inputs (detected by content, not by file name):
//   - DB-IP LITE "IP to Country" CSV (single file; the -v6 file is parsed the same way):
//       ip_range_start,ip_range_end,country_code
//   - MaxMind GeoLite2-Country CSV set, selected either as the -Blocks-IPv4.csv file (its IPv6
//       sibling and the Locations-*.csv are then located in the same directory) or as a directory
//       containing the set:
//       network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,...
//       with geoname_id -> country_iso_code resolved via the Locations CSV.
//
// The index is pre-merged (overlapping and adjacent ranges collapsed per country, and across the
// union of countries) because nftables interval sets reject overlapping elements and because the
// element count drives the kernel commit cost. Parse happens off the toggle path: ensureLoaded() is
// called from a worker thread and only re-parses when the file's (size, mtime) changed.
class CountryRangesLoader
{
public:
    struct Range4
    {
        uint32_t from = 0;
        uint32_t to = 0;   // inclusive
    };
    struct Range6
    {
        uint8_t from[16] = {};
        uint8_t to[16] = {};   // inclusive
    };

    static CountryRangesLoader &instance()
    {
        static CountryRangesLoader loader;
        return loader;
    }

    // Loads `path` if it is not already the loaded (size, mtime). Safe to call on every settings
    // change; the parse only runs when the file actually changed. The caller picks the thread —
    // a full parse takes ~0.3-1 s for a 500k-row CSV and must not run on the IPC thread. On failure
    // the previous index is KEPT (so a bad re-download never silently disables working rules) and
    // false is returned with *errOut populated.
    bool ensureLoaded(const std::string &path, std::string *errOut = nullptr);

    // True when the index currently reflects `path` (used to skip spawning a parse worker).
    bool isUpToDate(const std::string &path) const;

    // The countries present in the loaded index (lowercase, sorted).
    std::vector<std::string> countries() const;

    // Pre-merged, sorted ranges for one country; empty when the country is unknown. Copies are
    // bounded (largest country ≈ 30k ranges ≈ a few hundred KB).
    std::vector<Range4> ranges4(const std::string &countryCode) const;
    std::vector<Range6> ranges6(const std::string &countryCode) const;

    // Union of the merged ranges for `countryCodes` (unknown codes ignored). This is what the nft
    // set is populated with: merging the union also collapses overlaps BETWEEN countries, which
    // the kernel would otherwise reject on an interval set.
    std::vector<Range4> unionRanges4(const std::vector<std::string> &countryCodes) const;
    std::vector<Range6> unionRanges6(const std::vector<std::string> &countryCodes) const;

    // Diagnostics for the UI/log: which format was detected and how many ranges survived merging.
    std::string formatName() const;
    size_t totalRanges() const;

    // Pure parsing helpers, exposed for the framework-free unit tests.

    // Parses "a.b.c.d" into host order. Returns false on anything inet_pton rejects.
    static bool parseIp4(const std::string &s, uint32_t &out);
    // Parses a 16-byte IPv6 literal.
    static bool parseIp6(const std::string &s, uint8_t out[16]);
    // Parses "a.b.c.d/p" into an inclusive range.
    static bool parseCidr4(const std::string &s, Range4 &out);
    static bool parseCidr6(const std::string &s, Range6 &out);
    // Sorts by `from` and collapses overlapping AND adjacent ranges (next.from <= cur.to + 1).
    static void mergeRanges4(std::vector<Range4> &ranges);
    static void mergeRanges6(std::vector<Range6> &ranges);

    static constexpr size_t kMaxRows = 5'000'000;        // sanity bound; largest real DB ≈ 600k rows
    static constexpr size_t kMaxLineLen = 4096;

private:
    CountryRangesLoader() = default;

    enum class Format { Unknown, DbIp, GeoLite2 };

    // Both indexed per lowercase country code.
    struct Index
    {
        std::map<std::string, std::vector<Range4>> byCountry4;
        std::map<std::string, std::vector<Range6>> byCountry6;
        Format format = Format::Unknown;
        size_t totalRanges = 0;
    };

    static bool parseFile(const std::string &path, Index &index, std::string &errOut);
    static bool parseDbIpFile(const std::string &path, Index &index, std::string &errOut);
    static bool parseGeoLite2Set(const std::string &blocksPath, Index &index, std::string &errOut);
    static bool loadGeoLite2Locations(const std::string &locationsPath, std::map<std::string, std::string> &geonameToIso,
                                      std::string &errOut);
    static void finishIndex(Index &index);

    mutable std::mutex mutex_;
    Index index_;
    std::string loadedPath_;
    // Cache key: (size, mtime) of the successfully parsed file.
    long long loadedSize_ = -1;
    long long loadedMtime_ = -1;
};
