#include "network/heartbeat.hpp"

namespace madoka {

HelloMessage heartbeat_create_hello(const NodeId& sender, uint64_t timestamp) {
    return HelloMessage{
        .sender = sender,
        .timestamp = timestamp,
    };
}

bool heartbeat_process_hello(Topology* topo,
                             const HelloMessage& hello,
                             uint64_t current_time) {
    if (topo == nullptr) {
        return false;
    }

    Peer* peer = topology_find_peer(topo, hello.sender);
    if (peer == nullptr) {
        return false;
    }

    const uint64_t effective_time =
        (current_time > 0) ? current_time : hello.timestamp;
    peer->last_seen = effective_time;
    peer->state = PeerState::Connected;
    return true;
}

} // namespace madoka
