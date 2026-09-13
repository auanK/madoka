#ifndef MADOKA_NETWORK_TOPOLOGY_HPP
#define MADOKA_NETWORK_TOPOLOGY_HPP

#include "network/peer.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace madoka {

constexpr std::size_t MAX_TOPOLOGY_PEERS = 16;

struct Topology {
    std::vector<Peer> peers{};
};

void topology_init(Topology* topo);

bool topology_add_peer(Topology* topo,
                       const Peer& peer,
                       std::string* error = nullptr);

bool topology_remove_peer(Topology* topo, const NodeId& id);

Peer* topology_find_peer(Topology* topo, const NodeId& id);
const Peer* topology_find_peer(const Topology& topo, const NodeId& id);

Peer* topology_find_by_address(Topology* topo, const IPv6& virtual_address);
const Peer* topology_find_by_address(const Topology& topo,
                                     const IPv6& virtual_address);

bool topology_update_state(Topology* topo,
                           const NodeId& id,
                           PeerState new_state,
                           uint64_t timestamp = 0);

std::size_t topology_count(const Topology& topo);

std::size_t topology_active_neighbors_count(const Topology& topo,
                                            uint64_t current_time,
                                            uint64_t timeout_ms = 5000);

std::size_t topology_prune_stale(Topology* topo,
                                 uint64_t current_time,
                                 uint64_t timeout_ms = 5000);

void topology_clear(Topology* topo);

} // namespace madoka

#endif
