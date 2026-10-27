#include "dns_parse.h"

#include <arpa/inet.h>
#include <cstring>

namespace dns_parse {

namespace {

constexpr size_t kHeaderLen = 12;

uint16_t rdU16(const uint8_t *p)
{
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

} // namespace

std::optional<Header> parseHeader(const uint8_t *data, size_t len)
{
    if (data == nullptr || len < kHeaderLen) {
        return std::nullopt;
    }
    Header h;
    h.id = rdU16(data);
    h.qdcount = rdU16(data + 4);
    h.ancount = rdU16(data + 6);
    return h;
}

std::optional<std::string> decodeName(const uint8_t *data, size_t len, size_t offset, size_t *endOut)
{
    if (data == nullptr || offset >= len) {
        return std::nullopt;
    }
    std::string out;
    // Compression pointers may only point backwards; bound the hops so a malicious/corrupt packet
    // cannot make us loop.
    size_t hops = 0;
    size_t pos = offset;
    bool jumped = false;
    size_t end = offset;

    for (;;) {
        if (pos >= len) {
            return std::nullopt;
        }
        const uint8_t labelLen = data[pos];
        if (labelLen == 0) {
            pos += 1;
            if (!jumped) {
                end = pos;
            }
            break;
        }
        if ((labelLen & 0xC0) == 0xC0) {
            // compression pointer
            if (pos + 1 >= len) {
                return std::nullopt;
            }
            const size_t target = ((labelLen & 0x3F) << 8) | data[pos + 1];
            if (target >= pos) {
                return std::nullopt;   // only backwards pointers are legal
            }
            if (!jumped) {
                end = pos + 2;
                jumped = true;
            }
            if (++hops > 128) {
                return std::nullopt;
            }
            pos = target;
            continue;
        }
        if (labelLen > 63 || pos + 1 + labelLen > len) {
            return std::nullopt;
        }
        if (!out.empty()) {
            out += '.';
        }
        out.append(reinterpret_cast<const char *>(data + pos + 1), labelLen);
        pos += 1 + labelLen;
        if (out.size() > 253) {
            return std::nullopt;
        }
    }

    if (endOut != nullptr) {
        *endOut = end;
    }
    if (out.empty()) {
        return std::nullopt;   // root name is never a useful classification target here
    }
    return out;
}

std::optional<std::string> queryName(const uint8_t *data, size_t len)
{
    const auto h = parseHeader(data, len);
    if (!h || h->qdcount == 0) {
        return std::nullopt;
    }
    return decodeName(data, len, kHeaderLen, nullptr);
}

std::vector<std::string> answerAddresses(const uint8_t *data, size_t len)
{
    std::vector<std::string> out;
    const auto h = parseHeader(data, len);
    if (!h || h->ancount == 0) {
        return out;
    }

    // Skip the question section.
    size_t pos = kHeaderLen;
    for (uint16_t q = 0; q < h->qdcount; ++q) {
        size_t end = 0;
        const auto name = decodeName(data, len, pos, &end);
        if (!name) {
            return out;
        }
        pos = end + 4;   // qtype + qclass
        if (pos > len) {
            return out;
        }
    }

    for (uint16_t a = 0; a < h->ancount && pos + 10 <= len; ++a) {
        size_t end = 0;
        const auto name = decodeName(data, len, pos, &end);
        if (!name) {
            return out;
        }
        pos = end;
        if (pos + 10 > len) {
            return out;
        }
        const uint16_t type = rdU16(data + pos);
        const uint16_t rdlength = rdU16(data + pos + 8);
        pos += 10;
        if (pos + rdlength > len) {
            return out;
        }
        if (type == 1 && rdlength == 4) {
            char buf[INET_ADDRSTRLEN] = {};
            struct in_addr addr = {};
            std::memcpy(&addr, data + pos, 4);
            if (inet_ntop(AF_INET, &addr, buf, sizeof(buf)) != nullptr) {
                out.push_back(buf);
            }
        } else if (type == 28 && rdlength == 16) {
            char buf[INET6_ADDRSTRLEN] = {};
            struct in6_addr addr = {};
            std::memcpy(&addr, data + pos, 16);
            if (inet_ntop(AF_INET6, &addr, buf, sizeof(buf)) != nullptr) {
                out.push_back(buf);
            }
        }
        pos += rdlength;
    }
    return out;
}

} // namespace dns_parse
