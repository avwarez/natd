// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 avwarez

// natd/posix_io.hpp — IDatagramIo over POSIX UDP sockets (Linux, BSD, macOS).
//
// Optional adapter: the core library stays sans-I/O. All sockets are
// non-blocking; wait() multiplexes them with poll().
#pragma once

#include "natd/types.hpp"

#include <functional>
#include <map>

namespace natd {

class PosixDatagramIo : public IDatagramIo {
public:
    // bindIp: local address for every socket (host order), 0 = INADDR_ANY.
    explicit PosixDatagramIo(uint32_t bindIp = 0);
    ~PosixDatagramIo() override;
    PosixDatagramIo(const PosixDatagramIo&) = delete;
    PosixDatagramIo& operator=(const PosixDatagramIo&) = delete;

    std::optional<SocketId> openSocket(uint16_t preferredLocalPort) override;
    void closeSocket(SocketId) override;
    Endpoint localEndpoint(SocketId) const override;
    bool send(SocketId, const Endpoint& to, const uint8_t* data, size_t len) override;

    using RxFn = std::function<void(SocketId, const Endpoint& from, const uint8_t* data, size_t len)>;
    // Wait until `deadline` or until at least one datagram arrived, then
    // deliver every pending datagram. Returns the number delivered.
    int wait(TimePoint deadline, const RxFn& onRx);

    // Inside address the OS would use to reach destIp (UDP connect +
    // getsockname, nothing is sent). 0 if unknown. Fills
    // PeerInfo::localEndpoints when sockets are bound to INADDR_ANY.
    static uint32_t localIpToward(uint32_t destIp);

    size_t socketCount() const { return fds_.size(); }

private:
    uint32_t bindIp_;
    SocketId next_ = 1;
    std::map<SocketId, int> fds_;
};

} // namespace natd
