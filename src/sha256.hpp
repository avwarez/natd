// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// SHA-256 (FIPS 180-4), internal to natd: the session tokens are derived
// with it (sessionTokenFrom). Not part of the public API.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace natd::detail {

std::array<uint8_t, 32> sha256(const uint8_t* data, size_t len);

} // namespace natd::detail
