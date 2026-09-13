#include "network/discovery.hpp"

namespace madoka {

NeighborAdvertisement discovery_create_advertisement(const Peer& peer,
                                                     uint64_t timestamp,
                                                     uint64_t sequence_number) {
    return NeighborAdvertisement{
        .node_id = peer.id,
        .address = peer.virtual_address,
        .timestamp = (timestamp != 0) ? timestamp : peer.last_seen,
        .sequence_number = sequence_number,
    };
}

bool discovery_advertisement_equal(const NeighborAdvertisement& a,
                                   const NeighborAdvertisement& b) noexcept {
    return a.node_id == b.node_id && a.address == b.address &&
           a.timestamp == b.timestamp && a.sequence_number == b.sequence_number;
}

bool discovery_process_advertisement(Topology* topo,
                                     const NeighborAdvertisement& adv,
                                     uint64_t* last_known_seq,
                                     uint64_t current_time) {
    if (topo == nullptr) {
        return false;
    }

    if (last_known_seq != nullptr) {
        if (adv.sequence_number <= *last_known_seq) {
            return false;
        }
        *last_known_seq = adv.sequence_number;
    }

    const uint64_t effective_time =
        (current_time > 0) ? current_time : adv.timestamp;
    Peer* existing = topology_find_peer(topo, adv.node_id);
    if (existing != nullptr) {
        existing->virtual_address = adv.address;
        existing->last_seen = effective_time;
        existing->state = PeerState::Connected;
    } else {
        Peer new_peer = peer_create(
            adv.node_id, adv.address, "", PeerState::Connected, effective_time);
        topology_add_peer(topo, new_peer);
    }

    return true;
}

} // namespace madoka
