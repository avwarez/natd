// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

#include "natd/version.hpp"

#include "natd/agent.hpp"
#include "natd/protocol.hpp"

namespace natd {

static_assert(kWireVersion == proto::kVersion, "natd/version.hpp and protocol.hpp disagree");
static_assert(kOfferWireVersion == kOfferVersion, "natd/version.hpp and agent.hpp disagree");

const char* versionString() { return NATD_VERSION_STRING; }

} // namespace natd
