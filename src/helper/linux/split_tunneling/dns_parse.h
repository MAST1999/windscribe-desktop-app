#pragma once

// Pure, bounds-checked DNS wire-format helpers for the split-tunneling domain-regex feature
// (docs/plans/split-tunneling-regex-and-country.md §5.4). The resolver is a forward-and-inspect
// proxy: it never fabricates answers, it only reads the question name and the answer addresses
// out of queries/responses that pass through. Unit-tested framework-free
// (tests/dnsparsing.test.cpp).

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dns_parse {

struct Header
{
    uint16_t id = 0;
    uint16_t qdcount = 0;
    uint16_t ancount = 0;
};

// Parses the 12-byte DNS header. Returns nullopt for anything shorter or malformed.
std::optional<Header> parseHeader(const uint8_t *data, size_t len);

// Decodes a (possibly compressed) DNS name starting at offset. Returns nullopt when the name is
// malformed or the compression pointers do not stay within [0, len). The returned string is
// dot-joined, without a trailing root dot ("www.example.com").
std::optional<std::string> decodeName(const uint8_t *data, size_t len, size_t offset, size_t *endOut);

// The question name of a query (first question record; requires qdcount >= 1).
std::optional<std::string> queryName(const uint8_t *data, size_t len);

// Extracts A (type 1) / AAAA (type 28) answer addresses as dotted/hex strings. Follows compression
// pointers with the same bounds; skips every other record type. Best-effort: malformed answers are
// skipped, an empty result is valid.
std::vector<std::string> answerAddresses(const uint8_t *data, size_t len);

} // namespace dns_parse
