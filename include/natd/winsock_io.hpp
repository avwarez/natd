// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// natd/winsock_io.hpp — IDatagramIo over Winsock 2 UDP sockets (Windows).
//
// Same interface as PosixDatagramIo. Link with ws2_32. The constructor calls
// WSAStartup and the destructor WSACleanup. ICMP "port unreachable" reports
// (WSAECONNRESET on UDP sockets) are disabled with SIO_UDP_CONNRESET, so a
// probe to a closed port cannot break the receive loop.
#pragma once

#include "natd/types.hpp"

#include <cstdint>
#include <functional>
#include <map>

namespace natd {

class WinsockDatagramIo : public IDatagramIo {
public:
    explicit WinsockDatagramIo(uint32_t bindIp = 0);
    ~WinsockDatagramIo() override;
    WinsockDatagramIo(const WinsockDatagramIo&) = delete;
    WinsockDatagramIo& operator=(const WinsockDatagramIo&) = delete;

    bool ok() const { return started_; }   // WSAStartup succeeded

    std::optional<SocketId> openSocket(uint16_t preferredLocalPort) override;
    void closeSocket(SocketId) override;
    Endpoint localEndpoint(SocketId) const override;
    bool send(SocketId, const Endpoint& to, const uint8_t* data, size_t len) override;

    using RxFn = std::function<void(SocketId, const Endpoint& from, const uint8_t* data, size_t len)>;
    int wait(TimePoint deadline, const RxFn& onRx);

    // Inside address the OS would use to reach destIp (UDP connect +
    // getsockname, nothing is sent). 0 if unknown. Fills
    // PeerInfo::localEndpoints when sockets are bound to INADDR_ANY.
    static uint32_t localIpToward(uint32_t destIp);

    size_t socketCount() const { return socks_.size(); }

private:
    uint32_t bindIp_;
    bool started_ = false;
    SocketId next_ = 1;
    std::map<SocketId, uintptr_t> socks_;   // SOCKET values, kept opaque in the header
};

} // namespace natd
