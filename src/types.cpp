// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

#include "natd/types.hpp"

#include <cstdio>
#include <cstdlib>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#if defined(_MSC_VER)
#pragma comment(lib, "bcrypt.lib")
#endif
#elif defined(__linux__)
#include <cerrno>
#include <sys/random.h>
#include <sys/types.h>
#else
#include <unistd.h>   // getentropy (BSDs, macOS)
#endif

namespace natd {

// The operating system's CSPRNG: RFC 8489 §5 asks for cryptographically
// random transaction IDs, and the same source serves every other draw.
RandomBytesFn defaultRandomBytes() {
    return [](uint8_t* out, size_t len) {
#if defined(_WIN32)
        if (len && BCryptGenRandom(nullptr, out, ULONG(len), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) std::abort();
#elif defined(__linux__)
        while (len) {
            ssize_t n = getrandom(out, len, 0);
            if (n < 0) {
                if (errno == EINTR) continue;
                std::abort();   // no secure randomness: better stop than send guessable IDs
            }
            out += n;
            len -= size_t(n);
        }
#else
        while (len) {
            const size_t n = len < 256 ? len : 256;   // getentropy's limit per call
            if (getentropy(out, n) != 0) std::abort();
            out += n;
            len -= n;
        }
#endif
    };
}

std::string toString(const Endpoint& e) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "%u.%u.%u.%u:%u", (e.ip >> 24) & 255, (e.ip >> 16) & 255,
                  (e.ip >> 8) & 255, e.ip & 255, e.port);
    return buf;
}

std::optional<uint32_t> parseIp(const std::string& s) {
    uint32_t ip = 0;
    int parts = 0;
    size_t i = 0;
    while (parts < 4) {
        if (i >= s.size() || s[i] < '0' || s[i] > '9') return std::nullopt;
        uint32_t v = 0;
        size_t digits = 0;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
            v = v * 10 + uint32_t(s[i] - '0');
            if (++digits > 3 || v > 255) return std::nullopt;
            ++i;
        }
        ip = (ip << 8) | v;
        ++parts;
        if (parts < 4) {
            if (i >= s.size() || s[i] != '.') return std::nullopt;
            ++i;
        }
    }
    if (i != s.size()) return std::nullopt;
    return ip;
}

std::optional<Endpoint> parseEndpoint(const std::string& s) {
    auto c = s.rfind(':');
    if (c == std::string::npos) return std::nullopt;
    auto ip = parseIp(s.substr(0, c));
    if (!ip) return std::nullopt;
    std::string ps = s.substr(c + 1);
    if (ps.empty() || ps.size() > 5) return std::nullopt;
    unsigned long p = 0;
    for (char ch : ps) {
        if (ch < '0' || ch > '9') return std::nullopt;
        p = p * 10 + unsigned(ch - '0');
    }
    if (p == 0 || p > 65535) return std::nullopt;
    return Endpoint{*ip, uint16_t(p)};
}

} // namespace natd
