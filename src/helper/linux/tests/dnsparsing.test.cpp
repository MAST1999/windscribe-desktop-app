// Unit tests for the DNS wire-format helpers (dns_parse.h) that underpin the domain-regex
// split-tunneling resolver.  Builds real query/response packets by hand (including compressed
// names, the format every production resolver emits) and pins the parser's bounds behavior on
// truncated/hostile input.  No external test framework; returns the number of failed checks
// (0 on success).

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "../split_tunneling/dns_parse.h"

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

void pushU16(std::vector<uint8_t> &v, uint16_t x)
{
    v.push_back(static_cast<uint8_t>(x >> 8));
    v.push_back(static_cast<uint8_t>(x & 0xFF));
}

void pushU32(std::vector<uint8_t> &v, uint32_t x)
{
    v.push_back(static_cast<uint8_t>((x >> 24) & 0xFF));
    v.push_back(static_cast<uint8_t>((x >> 16) & 0xFF));
    v.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
    v.push_back(static_cast<uint8_t>(x & 0xFF));
}

// www.example.com A query, no compression (question only).
std::vector<uint8_t> buildQuery()
{
    std::vector<uint8_t> v;
    pushU16(v, 0x1234);   // id
    pushU16(v, 0x0100);   // flags: RD
    pushU16(v, 1);        // qdcount
    pushU16(v, 0);        // ancount
    pushU16(v, 0);
    pushU16(v, 0);
    v.push_back(3); v.insert(v.end(), { 'w', 'w', 'w' });
    v.push_back(7); v.insert(v.end(), { 'e', 'x', 'a', 'm', 'p', 'l', 'e' });
    v.push_back(3); v.insert(v.end(), { 'c', 'o', 'm' });
    v.push_back(0);
    pushU16(v, 1);        // qtype A
    pushU16(v, 1);        // qclass IN
    return v;
}

} // namespace

int main()
{
    // ---- query name ----
    const std::vector<uint8_t> query = buildQuery();
    const auto name = dns_parse::queryName(query.data(), query.size());
    VERIFY(name.has_value() && *name == "www.example.com");

    // Not a query (qdcount 0).
    {
        std::vector<uint8_t> q = query;
        q[4] = 0; q[5] = 0;
        VERIFY(!dns_parse::queryName(q.data(), q.size()).has_value());
    }

    // Truncated at every length: must never crash or read out of bounds.
    for (size_t cut = 0; cut < query.size(); ++cut) {
        const auto n = dns_parse::queryName(query.data(), cut);
        if (cut >= 12 + 17) {   // full header + full name bytes
            VERIFY(n.has_value());
        }
        // short inputs: either nullopt or a valid value; only absence of crash matters
        (void)n;
    }

    // ---- answer extraction, with compression -----------------------------------------------
    // Response: question + two answers. The FIRST answer name is a compression pointer to the
    // question name (offset 12, the form BIND/unbound/dnsmasq all emit); the second repeats it.
    std::vector<uint8_t> resp = query;
    resp[7] = 1;        // ancount = 1 in header

    // answer 1: ptr to offset 12, A 1.2.3.4, ttl 60
    resp.push_back(0xC0); resp.push_back(12);
    pushU16(resp, 1);        // type A
    pushU16(resp, 1);        // class IN
    pushU32(resp, 60);       // ttl
    pushU16(resp, 4);        // rdlength
    resp.insert(resp.end(), { 1, 2, 3, 4 });

    // answer 2: uncompressed name, AAAA ::1
    resp.push_back(3); resp.insert(resp.end(), { 'w', 'w', 'w' });
    resp.push_back(7); resp.insert(resp.end(), { 'e', 'x', 'a', 'm', 'p', 'l', 'e' });
    resp.push_back(3); resp.insert(resp.end(), { 'c', 'o', 'm' });
    resp.push_back(0);
    pushU16(resp, 28);       // type AAAA
    pushU16(resp, 1);
    pushU32(resp, 60);
    pushU16(resp, 16);
    resp.insert(resp.end(), 15, 0);
    resp.push_back(1);

    resp[7] = 2;   // ancount = 2
    {
        const auto addrs = dns_parse::answerAddresses(resp.data(), resp.size());
        VERIFY(addrs.size() == 2);
        VERIFY(addrs[0] == "1.2.3.4");
        VERIFY(addrs[1] == "::1");
    }

    // CNAME chains: the cname RR (type 5) must be skipped without derailing the parser.
    {
        std::vector<uint8_t> r = query;
        r[7] = 2;   // ancount = 2
        // answer 1: CNAME -> alias.example.com
        r.push_back(0xC0); r.push_back(12);
        pushU16(r, 5);           // type CNAME
        pushU16(r, 1);
        pushU32(r, 300);
        pushU16(r, 19);          // rdlength: uncompressed alias.example.com (1+5 + 1+7 + 1+3 + 1)
        r.push_back(5); r.insert(r.end(), { 'a', 'l', 'i', 'a', 's' });
        r.push_back(7); r.insert(r.end(), { 'e', 'x', 'a', 'm', 'p', 'l', 'e' });
        r.push_back(3); r.insert(r.end(), { 'c', 'o', 'm' });
        r.push_back(0);
        // answer 2: alias.example.com (uncompressed) A 9.9.9.9
        r.push_back(5); r.insert(r.end(), { 'a', 'l', 'i', 'a', 's' });
        r.push_back(7); r.insert(r.end(), { 'e', 'x', 'a', 'm', 'p', 'l', 'e' });
        r.push_back(3); r.insert(r.end(), { 'c', 'o', 'm' });
        r.push_back(0);
        pushU16(r, 1);
        pushU16(r, 1);
        pushU32(r, 60);
        pushU16(r, 4);
        r.insert(r.end(), { 9, 9, 9, 9 });

        const auto addrs = dns_parse::answerAddresses(r.data(), r.size());
        VERIFY(addrs.size() == 1 && addrs[0] == "9.9.9.9");
    }

    // Hostile inputs: nonsense pointers must be rejected, not followed.
    {
        std::vector<uint8_t> bad = { 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,   // header, qdcount=1
                                     0xC0, 0x0C };                          // pointer to itself (offset 12)
        VERIFY(!dns_parse::decodeName(bad.data(), bad.size(), 12, nullptr).has_value());
        // forward pointer is illegal too
        bad[13] = 0x20;   // points forward (offset 32)
        VERIFY(!dns_parse::decodeName(bad.data(), bad.size(), 12, nullptr).has_value());
        // huge hop count via a pointer chain is bounded (no hang)
        std::vector<uint8_t> chain(64, 0);
        chain[0] = 0xC0; chain[1] = 0x02;
        for (size_t i = 2; i + 1 < chain.size(); i += 2) {
            chain[i] = 0xC0;
            chain[i + 1] = static_cast<uint8_t>(i - 2);
        }
        VERIFY(!dns_parse::decodeName(chain.data(), chain.size(), 0, nullptr).has_value());
    }

    // answerAddresses on truncated/garbage input must stay empty, never crash.
    {
        const auto addrs = dns_parse::answerAddresses(resp.data(), resp.size() / 2);
        (void)addrs;
        const auto none = dns_parse::answerAddresses(nullptr, 0);
        VERIFY(none.empty());
    }

    if (g_failures == 0) {
        printf("dnsparsing.test: all checks passed\n");
        return 0;
    }
    printf("dnsparsing.test: %d check(s) FAILED\n", g_failures);
    return 1;
}
