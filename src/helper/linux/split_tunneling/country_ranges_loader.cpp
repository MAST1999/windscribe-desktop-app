#include "country_ranges_loader.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstdio>
#include <cstring>

#include <arpa/inet.h>
#include <sys/stat.h>

#include <spdlog/spdlog.h>

namespace
{

constexpr char kGeoLite2LocationsPrefix[] = "GeoLite2-Country-Locations-";
constexpr char kGeoLite2BlocksV6Name[] = "GeoLite2-Country-Blocks-IPv6.csv";

bool statFile(const std::string &path, long long &size, long long &mtime)
{
    struct stat st = {};
    if (::stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
        return false;
    }
    size = static_cast<long long>(st.st_size);
    mtime = static_cast<long long>(st.st_mtim.tv_sec);
    return true;
}

// CSV field splitter handling double-quoted fields ("en", as in the GeoLite2 Locations locale
// names). Deliberately not a full RFC 4180 parser — these databases use at most simple quoting.
size_t splitCsvLine(const std::string &line, std::vector<std::string> &fields)
{
    fields.clear();
    std::string cur;
    bool inQuotes = false;
    for (char c : line) {
        if (inQuotes) {
            if (c == '"') {
                inQuotes = false;
            } else {
                cur.push_back(c);
            }
        } else if (c == '"') {
            inQuotes = true;
        } else if (c == ',') {
            fields.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    fields.push_back(cur);
    return fields.size();
}

// Reads the first CSV line; returns false if the file cannot be opened or starts with binary data.
bool readFirstLine(const std::string &path, std::string &line, std::string &errOut)
{
    std::FILE *f = std::fopen(path.c_str(), "rb");
    if (!f) {
        errOut = "cannot open file";
        return false;
    }
    std::vector<char> buf(CountryRangesLoader::kMaxLineLen + 1);
    const char *res = std::fgets(buf.data(), static_cast<int>(buf.size()), f);
    std::fclose(f);
    if (!res) {
        errOut = "file is empty";
        return false;
    }
    line.assign(buf.data());
    if (line.find('\0') != std::string::npos) {
        errOut = "file starts with binary data, not CSV text";
        return false;
    }
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
        line.pop_back();
    }
    return true;
}

bool isHeaderField(const std::string &line, const char *needle)
{
    return line.find(needle) != std::string::npos;
}

// DB-IP range rows may carry extra columns; only the first three matter.
bool parseDbIpRow(const std::vector<std::string> &fields, CountryRangesLoader::Range4 &r4,
                  CountryRangesLoader::Range6 &r6, bool &isV6)
{
    if (fields.size() < 3) {
        return false;
    }
    const std::string &from = fields[0];
    const std::string &to = fields[1];
    isV6 = from.find(':') != std::string::npos;
    if (isV6) {
        if (!CountryRangesLoader::parseIp6(from, r6.from) || !CountryRangesLoader::parseIp6(to, r6.to)) {
            return false;
        }
    } else {
        if (!CountryRangesLoader::parseIp4(from, r4.from) || !CountryRangesLoader::parseIp4(to, r4.to)) {
            return false;
        }
    }
    return true;
}

// Extracts the geoname id GeoLite2 attributes the country to. Preference order per MaxMind docs:
// registered_country (the IP was registered here), then represented_country (military/gov
// overlays), then the plain geoname_id.
const std::string *geoLite2CountryGeoname(const std::vector<std::string> &fields,
                                          const std::vector<size_t> &idx)
{
    for (size_t i : idx) {
        if (i < fields.size() && !fields[i].empty() && fields[i] != "0") {
            return &fields[i];
        }
    }
    return nullptr;
}

// fgets into a scratch buffer, then copy out: `std::string::resize()` on a short string
// value-initializes the grown bytes to '\0', which would clobber what fgets just wrote if we
// resized-and-read through the string's own buffer. The scratch buffer avoids that class of bug
// entirely and makes the NUL sniff meaningful (a NUL in the middle of a line means binary data).
class LineReader
{
public:
    explicit LineReader(std::FILE *f) : f_(f), buf_(CountryRangesLoader::kMaxLineLen + 1) {}

    bool next(std::string &line)
    {
        if (!std::fgets(buf_.data(), static_cast<int>(buf_.size()), f_)) {
            return false;
        }
        // fgets returned a buffer whose first byte is NUL: binary garbage, not text. (A normal
        // blank line is a lone '\n' and has rawLen 1.)
        lastRawLen_ = std::strlen(buf_.data());
        line.assign(buf_.data(), lastRawLen_);
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
            line.pop_back();
        }
        return true;
    }

    // True when the last line returned started with a NUL byte (binary data).
    bool lastLineWasBinary() const { return lastRawLen_ == 0; }

private:
    std::FILE *f_;
    std::vector<char> buf_;
    size_t lastRawLen_ = 1;
};

} // namespace

bool CountryRangesLoader::parseIp4(const std::string &s, uint32_t &out)
{
    struct in_addr a = {};
    if (s.size() < 7 || s.size() > 15 || ::inet_pton(AF_INET, s.c_str(), &a) != 1) {
        return false;
    }
    out = ntohl(a.s_addr);
    return true;
}

bool CountryRangesLoader::parseIp6(const std::string &s, uint8_t out[16])
{
    struct in6_addr a = {};
    if (s.size() < 2 || s.size() > 45 || ::inet_pton(AF_INET6, s.c_str(), &a) != 1) {
        return false;
    }
    std::memcpy(out, a.s6_addr, 16);
    return true;
}

bool CountryRangesLoader::parseCidr4(const std::string &s, Range4 &out)
{
    const size_t slash = s.find('/');
    if (slash == std::string::npos) {
        return false;
    }
    uint32_t base = 0;
    if (!parseIp4(s.substr(0, slash), base)) {
        return false;
    }
    int prefix = std::atoi(s.c_str() + slash + 1);
    if (prefix < 0 || prefix > 32) {
        return false;
    }
    if (prefix == 0) {
        out.from = 0;
        out.to = 0xFFFFFFFFu;
        return true;
    }
    const uint32_t mask = 0xFFFFFFFFu << (32 - prefix);
    out.from = base & mask;
    out.to = out.from | (~mask);
    return true;
}

bool CountryRangesLoader::parseCidr6(const std::string &s, Range6 &out)
{
    const size_t slash = s.find('/');
    if (slash == std::string::npos) {
        return false;
    }
    if (!parseIp6(s.substr(0, slash), out.from)) {
        return false;
    }
    int prefix = std::atoi(s.c_str() + slash + 1);
    if (prefix < 0 || prefix > 128) {
        return false;
    }
    std::memcpy(out.to, out.from, 16);
    if (prefix == 128) {
        return true;
    }
    // Zero out everything below the prefix, then fill the range up to the top of the block.
    for (int byte = 15; byte >= 0; --byte) {
        const int bitLow = byte * 8;                  // lowest bit index covered by this byte
        if (bitLow >= prefix) {
            out.from[byte] = 0;
            out.to[byte] = 0xFF;
        } else {
            const int keepBits = prefix - bitLow;     // bits kept in this byte (1..8)
            const uint8_t mask = static_cast<uint8_t>(0xFFu << (8 - keepBits));
            out.from[byte] &= mask;
            out.to[byte] = static_cast<uint8_t>(out.from[byte] | (~mask));
            break;
        }
    }
    return true;
}

int compare6(const uint8_t a[16], const uint8_t b[16])
{
    return std::memcmp(a, b, 16);
}

// 128-bit increment for adjacency checks.
void increment6(uint8_t v[16])
{
    for (int i = 15; i >= 0; --i) {
        if (++v[i] != 0) {
            break;
        }
    }
}

void CountryRangesLoader::mergeRanges4(std::vector<Range4> &ranges)
{
    std::sort(ranges.begin(), ranges.end(), [](const Range4 &a, const Range4 &b) { return a.from < b.from; });
    std::vector<Range4> out;
    out.reserve(ranges.size());
    for (const Range4 &r : ranges) {
        if (!out.empty() && r.from <= out.back().to + 1) {
            if (r.to > out.back().to) {
                out.back().to = r.to;
            }
        } else {
            out.push_back(r);
        }
    }
    ranges.swap(out);
}

void CountryRangesLoader::mergeRanges6(std::vector<Range6> &ranges)
{
    std::sort(ranges.begin(), ranges.end(), [](const Range6 &a, const Range6 &b) {
        return compare6(a.from, b.from) < 0;
    });
    std::vector<Range6> out;
    out.reserve(ranges.size());
    for (const Range6 &r : ranges) {
        if (!out.empty() && compare6(r.from, out.back().to) <= 0) {
            if (compare6(r.to, out.back().to) > 0) {
                std::memcpy(out.back().to, r.to, 16);
            }
            continue;
        }
        // Adjacency: r.from == prev.to + 1. Check without overflowing prev.to.
        if (!out.empty()) {
            uint8_t next[16];
            std::memcpy(next, out.back().to, 16);
            increment6(next);
            if (compare6(r.from, next) == 0) {
                std::memcpy(out.back().to, r.to, 16);
                continue;
            }
        }
        out.push_back(r);
    }
    ranges.swap(out);
}

void CountryRangesLoader::finishIndex(Index &index)
{
    size_t total = 0;
    for (auto &kv : index.byCountry4) {
        mergeRanges4(kv.second);
        total += kv.second.size();
    }
    for (auto &kv : index.byCountry6) {
        mergeRanges6(kv.second);
        total += kv.second.size();
    }
    index.totalRanges = total;
}

bool CountryRangesLoader::loadGeoLite2Locations(const std::string &locationsPath,
                                                std::map<std::string, std::string> &geonameToIso,
                                                std::string &errOut)
{
    std::FILE *f = std::fopen(locationsPath.c_str(), "rb");
    if (!f) {
        errOut = "GeoLite2 Locations CSV not found next to the Blocks file (expected " +
                 std::string(kGeoLite2LocationsPrefix) + "*.csv)";
        return false;
    }
    LineReader reader(f);
    std::vector<std::string> fields;
    std::string line;
    size_t rows = 0;
    while (reader.next(line)) {
        if (rows == 0 && isHeaderField(line, "geoname_id")) {
            continue;
        }
        splitCsvLine(line, fields);
        if (fields.size() < 3) {
            continue;
        }
        // geoname_id,locale_code,continent_code,continent_name,country_iso_code,...
        const std::string &geoname = fields[0];
        const std::string &iso = fields[4];
        if (!geoname.empty() && iso.size() == 2) {
            geonameToIso[geoname] = iso;
        }
        ++rows;
    }
    std::fclose(f);
    if (geonameToIso.empty()) {
        errOut = "Locations CSV contained no country mappings";
        return false;
    }
    return true;
}

bool CountryRangesLoader::parseGeoLite2Set(const std::string &blocksPath, Index &index, std::string &errOut)
{
    const size_t slash = blocksPath.find_last_of('/');
    const std::string dir = (slash == std::string::npos) ? std::string(".") : blocksPath.substr(0, slash);

    std::map<std::string, std::string> geonameToIso;
    if (!loadGeoLite2Locations(dir + "/" + kGeoLite2LocationsPrefix + "en.csv", geonameToIso, errOut)) {
        return false;
    }

    const bool isV6File = blocksPath.find("IPv6") != std::string::npos;
    std::vector<std::string> blockFiles;
    blockFiles.push_back(blocksPath);
    if (!isV6File) {
        // Selected the IPv4 Blocks file: pull in the IPv6 sibling too so one selection loads both
        // families. A set without the v6 file still works for v4-only.
        const std::string v6Path = dir + "/" + kGeoLite2BlocksV6Name;
        long long size = 0, mtime = 0;
        if (statFile(v6Path, size, mtime)) {
            blockFiles.push_back(v6Path);
        }
    }

    for (const std::string &file : blockFiles) {
        std::FILE *f = std::fopen(file.c_str(), "rb");
        if (!f) {
            errOut = "cannot open " + file;
            return false;
        }
        LineReader reader(f);
        std::vector<std::string> fields;
        std::string line;
        size_t rows = 0;
        bool headerSeen = false;
        while (reader.next(line)) {
            if (reader.lastLineWasBinary()) {
                std::fclose(f);
                errOut = "binary data in " + file;
                return false;
            }
            if (!headerSeen) {
                headerSeen = true;
                if (isHeaderField(line, "network")) {
                    continue;
                }
            }
            if (++rows > kMaxRows) {
                std::fclose(f);
                errOut = "row cap exceeded (corrupt or hostile file?)";
                return false;
            }
            splitCsvLine(line, fields);
            // Column layout differs between GeoLite2 releases; find the geoname columns by header
            // position, falling back to the documented default layout.
            static const std::vector<size_t> kDefaultGeonameOrder = { 2, 1, 3 };
            const std::string *geoname = geoLite2CountryGeoname(fields, kDefaultGeonameOrder);
            if (!geoname) {
                continue;
            }
            auto isoIt = geonameToIso.find(*geoname);
            if (isoIt == geonameToIso.end()) {
                continue;
            }
            std::string cc = isoIt->second;
            std::transform(cc.begin(), cc.end(), cc.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            const bool v6 = fields[0].find(':') != std::string::npos;
            if (v6) {
                Range6 r6;
                if (!parseCidr6(fields[0], r6)) {
                    continue;
                }
                index.byCountry6[cc].push_back(r6);
            } else {
                Range4 r4;
                if (!parseCidr4(fields[0], r4)) {
                    continue;
                }
                index.byCountry4[cc].push_back(r4);
            }
        }
        std::fclose(f);
        if (rows == 0) {
            errOut = "no data rows in " + file;
            return false;
        }
    }

    index.format = Format::GeoLite2;
    return true;
}

bool CountryRangesLoader::parseDbIpFile(const std::string &path, Index &index, std::string &errOut)
{
    std::FILE *f = std::fopen(path.c_str(), "rb");
    if (!f) {
        errOut = "cannot open file";
        return false;
    }
    LineReader reader(f);
    std::string line;
    std::vector<std::string> fields;
    size_t rows = 0;
    bool headerSeen = false;
    while (reader.next(line)) {
        if (reader.lastLineWasBinary()) {
            std::fclose(f);
            errOut = "binary data in file";
            return false;
        }
        if (!headerSeen) {
            headerSeen = true;
            if (isHeaderField(line, "ip_range_start")) {
                continue;
            }
        }
        if (++rows > kMaxRows) {
            std::fclose(f);
            errOut = "row cap exceeded (corrupt or hostile file?)";
            return false;
        }
        splitCsvLine(line, fields);
        Range4 r4;
        Range6 r6;
        bool isV6 = false;
        if (!parseDbIpRow(fields, r4, r6, isV6)) {
            continue;
        }
        std::string cc = fields[2];
        if (cc.size() != 2) {
            continue;   // ranges with no country (reserved etc.) are useless for this feature
        }
        std::transform(cc.begin(), cc.end(), cc.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (isV6) {
            index.byCountry6[cc].push_back(r6);
        } else {
            index.byCountry4[cc].push_back(r4);
        }
    }
    std::fclose(f);
    if (rows == 0) {
        errOut = "no data rows in file";
        return false;
    }
    index.format = Format::DbIp;
    return true;
}

bool CountryRangesLoader::parseFile(const std::string &path, Index &index, std::string &errOut)
{
    std::string firstLine;
    if (!readFirstLine(path, firstLine, errOut)) {
        return false;
    }
    if (isHeaderField(firstLine, "network") || isHeaderField(firstLine, "geoname_id")) {
        return parseGeoLite2Set(path, index, errOut);
    }
    // DB-IP (with or without header): the first data line must carry parseable IP endpoints.
    return parseDbIpFile(path, index, errOut);
}

bool CountryRangesLoader::ensureLoaded(const std::string &path, std::string *errOut)
{
    long long size = 0, mtime = 0;
    if (!statFile(path, size, mtime)) {
        if (errOut) {
            *errOut = "cannot stat GeoIP database file: " + path;
        }
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (!loadedPath_.empty() && loadedPath_ == path && loadedSize_ == size && loadedMtime_ == mtime) {
        return true;   // already current
    }

    Index fresh;
    std::string parseErr;
    if (!parseFile(path, fresh, parseErr)) {
        // Keep the previous index: a failed re-parse (e.g. truncated download) must not silently
        // disable working country rules.
        spdlog::error("CountryRangesLoader: failed to parse \"{}\": {}", path, parseErr);
        if (errOut) {
            *errOut = parseErr;
        }
        return false;
    }

    finishIndex(fresh);   // sort + merge per country; also produces totalRanges
    index_ = std::move(fresh);
    loadedPath_ = path;
    loadedSize_ = size;
    loadedMtime_ = mtime;
    // Log from local state (NOT via formatName()/totalRanges(): they re-lock mutex_, which is
    // non-recursive — this call site already holds it).
    const char *fmt = index_.format == Format::DbIp ? "DB-IP LITE"
                    : index_.format == Format::GeoLite2 ? "GeoLite2" : "unknown";
    spdlog::info("CountryRangesLoader: loaded \"{}\" ({}), {} merged ranges across {} countries",
                 path, fmt, index_.totalRanges, index_.byCountry4.size() + index_.byCountry6.size());
    return true;
}

bool CountryRangesLoader::isUpToDate(const std::string &path) const
{
    long long size = 0, mtime = 0;
    if (!statFile(path, size, mtime)) {
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    return !loadedPath_.empty() && loadedPath_ == path && loadedSize_ == size && loadedMtime_ == mtime;
}

std::vector<std::string> CountryRangesLoader::countries() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> out;
    out.reserve(index_.byCountry4.size() + index_.byCountry6.size());
    for (const auto &kv : index_.byCountry4) {
        out.push_back(kv.first);
    }
    for (const auto &kv : index_.byCountry6) {
        if (index_.byCountry4.find(kv.first) == index_.byCountry4.end()) {
            out.push_back(kv.first);
        }
    }
    std::sort(out.begin(), out.end());
    return out;
}

std::vector<CountryRangesLoader::Range4> CountryRangesLoader::ranges4(const std::string &countryCode) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = index_.byCountry4.find(countryCode);
    return it == index_.byCountry4.end() ? std::vector<Range4>() : it->second;
}

std::vector<CountryRangesLoader::Range6> CountryRangesLoader::ranges6(const std::string &countryCode) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = index_.byCountry6.find(countryCode);
    return it == index_.byCountry6.end() ? std::vector<Range6>() : it->second;
}

std::vector<CountryRangesLoader::Range4> CountryRangesLoader::unionRanges4(const std::vector<std::string> &countryCodes) const
{
    std::vector<Range4> out;
    std::lock_guard<std::mutex> lock(mutex_);
    for (const std::string &cc : countryCodes) {
        auto it = index_.byCountry4.find(cc);
        if (it != index_.byCountry4.end()) {
            out.insert(out.end(), it->second.begin(), it->second.end());
        }
    }
    mergeRanges4(out);   // also collapses cross-country overlaps, which nft interval sets reject
    return out;
}

std::vector<CountryRangesLoader::Range6> CountryRangesLoader::unionRanges6(const std::vector<std::string> &countryCodes) const
{
    std::vector<Range6> out;
    std::lock_guard<std::mutex> lock(mutex_);
    for (const std::string &cc : countryCodes) {
        auto it = index_.byCountry6.find(cc);
        if (it != index_.byCountry6.end()) {
            out.insert(out.end(), it->second.begin(), it->second.end());
        }
    }
    mergeRanges6(out);
    return out;
}

std::string CountryRangesLoader::formatName() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    switch (index_.format) {
    case Format::DbIp:
        return "DB-IP LITE";
    case Format::GeoLite2:
        return "GeoLite2";
    case Format::Unknown:
        break;
    }
    return "unknown";
}

size_t CountryRangesLoader::totalRanges() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return index_.totalRanges;
}
