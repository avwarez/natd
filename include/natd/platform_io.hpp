// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// natd/platform_io.hpp — the socket adapter of the current platform as
// natd::PlatformDatagramIo (WinsockDatagramIo on Windows, PosixDatagramIo
// elsewhere). Both expose the same constructor, IDatagramIo and wait().
#pragma once

#ifdef _WIN32
#include "natd/winsock_io.hpp"
namespace natd { using PlatformDatagramIo = WinsockDatagramIo; }
#else
#include "natd/posix_io.hpp"
namespace natd { using PlatformDatagramIo = PosixDatagramIo; }
#endif
