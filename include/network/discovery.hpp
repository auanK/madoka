#ifndef MADOKA_NETWORK_DISCOVERY_HPP
#define MADOKA_NETWORK_DISCOVERY_HPP

#include "core/config.hpp"
#include "network/peer.hpp"
#include "network/topology.hpp"

#include <cstdint>

namespace madoka {

struct NeighborAdvertisement {
    NodeId node_id{};

    IPv6 address{};

    uint64_t timestamp{0};

    uint64_t sequence_number{0};

    bool operator==(const NeighborAdvertisement& other) const = default;
};

NeighborAdvertisement discovery_create_advertisement(
    const Peer& peer, uint64_t timestamp = 0, uint64_t sequence_number = 0);

bool discovery_advertisement_equal(const NeighborAdvertisement& a,
                                   const NeighborAdvertisement& b) noexcept;

bool discovery_process_advertisement(Topology* topo,
                                     const NeighborAdvertisement& adv,
                                     uint64_t* last_known_seq,
                                     uint64_t current_time = 0);

} // namespace madoka

#endif
