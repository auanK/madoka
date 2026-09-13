#include "network/peer.hpp"

namespace madoka {

std::string_view to_string(PeerState state) noexcept {
    switch (state) {
        case PeerState::Unknown:
            return "Unknown";
        case PeerState::Connecting:
            return "Connecting";
        case PeerState::Connected:
            return "Connected";
        case PeerState::Disconnected:
            return "Disconnected";
    }
    return "Unknown";
}

Peer peer_create(const NodeId& id,
                 const IPv6& virtual_address,
                 std::string_view endpoint,
                 PeerState state,
                 uint64_t last_seen) {
    return Peer{
        .id = id,
        .virtual_address = virtual_address,
        .endpoint = std::string(endpoint),
        .state = state,
        .last_seen = last_seen,
    };
}

void peer_update_state(Peer* peer, PeerState new_state, uint64_t timestamp) {
    if (!peer) {
        return;
    }
    peer->state = new_state;
    if (timestamp > 0) {
        peer->last_seen = timestamp;
    }
}

bool peer_is_alive(const Peer& peer,
                   uint64_t current_time,
                   uint64_t timeout_ms) noexcept {
    if (peer.state != PeerState::Connected) {
        return false;
    }
    if (peer.last_seen == 0 || current_time < peer.last_seen) {
        return false;
    }
    return (current_time - peer.last_seen) <= timeout_ms;
}

bool peer_equal(const Peer& a, const Peer& b) noexcept {
    return a.id == b.id;
}

} // namespace madoka
