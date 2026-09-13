#ifndef MADOKA_NETWORK_PEER_HPP
#define MADOKA_NETWORK_PEER_HPP

#include "core/config.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace madoka {

enum class PeerState : uint8_t {
    Unknown = 0,
    Connecting = 1,
    Connected = 2,
    Disconnected = 3
};

std::string_view to_string(PeerState state) noexcept;

struct Peer {
    NodeId id{};

    IPv6 virtual_address{};

    std::string endpoint{};

    PeerState state{PeerState::Unknown};

    uint64_t last_seen{0};
};

Peer peer_create(const NodeId& id,
                 const IPv6& virtual_address,
                 std::string_view endpoint = {},
                 PeerState state = PeerState::Unknown,
                 uint64_t last_seen = 0);

void peer_update_state(Peer* peer, PeerState new_state, uint64_t timestamp = 0);

bool peer_is_alive(const Peer& peer,
                   uint64_t current_time,
                   uint64_t timeout_ms = 5000) noexcept;

bool peer_equal(const Peer& a, const Peer& b) noexcept;

} // namespace madoka

#endif
