#ifndef MADOKA_NETWORK_DISTANCE_VECTOR_HPP
#define MADOKA_NETWORK_DISTANCE_VECTOR_HPP

#include "core/config.hpp"
#include "network/route_advertisement.hpp"
#include "network/routing.hpp"

#include <cstdint>
#include <unordered_map>

namespace madoka {

struct RouteOriginState {
    uint64_t generation{0};
    uint64_t sequence{0};
};

using RouteOriginStates =
    std::unordered_map<NodeId, RouteOriginState, NodeIdHasher>;

bool distance_vector_update(RouteTable& table,
                            const NodeId& neighbor,
                            const RouteAdvertisement& advertisement,
                            uint64_t current_time = 0,
                            uint32_t link_cost = 1,
                            uint64_t* last_known_seq = nullptr,
                            bool* routes_changed = nullptr);

bool distance_vector_update(RouteTable& table,
                            const NodeId& neighbor,
                            const RouteAdvertisement& advertisement,
                            uint64_t current_time,
                            uint32_t link_cost,
                            RouteOriginStates* origin_states,
                            bool* routes_changed = nullptr);

} // namespace madoka

#endif
