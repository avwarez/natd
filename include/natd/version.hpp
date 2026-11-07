// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// natd/version.hpp — the library version and the versions of its formats.
//
// The library follows Semantic Versioning (https://semver.org): MAJOR.MINOR.
// PATCH. While MAJOR is 0, a MINOR release may change the API; a PATCH
// release never does. The formats on the wire have versions of their own,
// independent of the library's: one is raised only by an incompatible change
// of that format, and the decoders keep reading the older versions they list.
// CHANGELOG.md says what each release changed.
#pragma once

#include <cstdint>

#define NATD_VERSION_MAJOR 0
#define NATD_VERSION_MINOR 1
#define NATD_VERSION_PATCH 3
#define NATD_VERSION_STRING "0.1.3"
// For #if: 0.1.0 = 100, 1.2.3 = 10203.
#define NATD_VERSION (NATD_VERSION_MAJOR * 10000 + NATD_VERSION_MINOR * 100 + NATD_VERSION_PATCH)

namespace natd {

constexpr int kVersionMajor = NATD_VERSION_MAJOR;
constexpr int kVersionMinor = NATD_VERSION_MINOR;
constexpr int kVersionPatch = NATD_VERSION_PATCH;

// The version of the compiled library, which may differ from the headers'
// (NATD_VERSION_STRING) when an application links a library built apart.
const char* versionString();

// Formats on the wire
constexpr uint8_t kWireVersion = 1;       // natd messages (proto::kVersion): probes, punches, streams
constexpr uint8_t kPeerInfoVersion = 3;   // encodePeerInfo; decodePeerInfo reads 1 to 3
constexpr uint8_t kOfferWireVersion = 1;  // encodeOffer (kOfferVersion)

} // namespace natd
