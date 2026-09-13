#include "network/topology.hpp"

#include <algorithm>

namespace madoka {

void topology_init(Topology* topo) {
    if (!topo) {
        return;
    }
    topo->peers.clear();
    topo->peers.reserve(MAX_TOPOLOGY_PEERS);
}

bool topology_add_peer(Topology* topo, const Peer& peer, std::string* error) {
    if (!topo) {
        if (error) {
            *error = "Topology pointer is null";
        }
        return false;
    }

    if (topology_find_peer(*topo, peer.id) != nullptr) {
        if (error) {
            *error = "Peer with identical Node ID already exists in topology";
        }
        return false;
    }

    if (topo->peers.size() >= MAX_TOPOLOGY_PEERS) {
        if (error) {
            *error =
                "Topology capacity limit reached: maximum 16 peers allowed";
        }
        return false;
    }

    topo->peers.push_back(peer);
    return true;
}

bool topology_remove_peer(Topology* topo, const NodeId& id) {
    if (!topo) {
        return false;
    }
    const auto it = std::find_if(
        topo->peers.begin(), topo->peers.end(), [&](const Peer& p) {
            return p.id == id;
        });
    if (it != topo->peers.end()) {
        topo->peers.erase(it);
        return true;
    }
    return false;
}

Peer* topology_find_peer(Topology* topo, const NodeId& id) {
    if (!topo) {
        return nullptr;
    }
    const auto it = std::find_if(
        topo->peers.begin(), topo->peers.end(), [&](const Peer& p) {
            return p.id == id;
        });
    return (it != topo->peers.end()) ? &(*it) : nullptr;
}

const Peer* topology_find_peer(const Topology& topo, const NodeId& id) {
    const auto it =
        std::find_if(topo.peers.begin(), topo.peers.end(), [&](const Peer& p) {
            return p.id == id;
        });
    return (it != topo.peers.end()) ? &(*it) : nullptr;
}

Peer* topology_find_by_address(Topology* topo, const IPv6& virtual_address) {
    if (!topo) {
        return nullptr;
    }
    const auto it = std::find_if(
        topo->peers.begin(), topo->peers.end(), [&](const Peer& p) {
            return p.virtual_address == virtual_address;
        });
    return (it != topo->peers.end()) ? &(*it) : nullptr;
}

const Peer* topology_find_by_address(const Topology& topo,
                                     const IPv6& virtual_address) {
    const auto it =
        std::find_if(topo.peers.begin(), topo.peers.end(), [&](const Peer& p) {
            return p.virtual_address == virtual_address;
        });
    return (it != topo.peers.end()) ? &(*it) : nullptr;
}

bool topology_update_state(Topology* topo,
                           const NodeId& id,
                           PeerState new_state,
                           uint64_t timestamp) {
    Peer* peer = topology_find_peer(topo, id);
    if (!peer) {
        return false;
    }
    peer_update_state(peer, new_state, timestamp);
    return true;
}

std::size_t topology_count(const Topology& topo) {
    return topo.peers.size();
}

std::size_t topology_active_neighbors_count(const Topology& topo,
                                            uint64_t current_time,
                                            uint64_t timeout_ms) {
    return static_cast<std::size_t>(
        std::count_if(topo.peers.begin(), topo.peers.end(), [&](const Peer& p) {
            return peer_is_alive(p, current_time, timeout_ms);
        }));
}

std::size_t topology_prune_stale(Topology* topo,
                                 uint64_t current_time,
                                 uint64_t timeout_ms) {
    if (!topo) {
        return 0;
    }
    std::size_t pruned_count = 0;
    for (auto& peer : topo->peers) {
        if (peer.state == PeerState::Connected &&
            !peer_is_alive(peer, current_time, timeout_ms)) {
            peer.state = PeerState::Disconnected;
            ++pruned_count;
        }
    }
    return pruned_count;
}

void topology_clear(Topology* topo) {
    if (!topo) {
        return;
    }
    topo->peers.clear();
}

} // namespace madoka
