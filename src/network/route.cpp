#include "network/route.hpp"

namespace madoka {

Route route_create(const IPv6& destination,
                   const NodeId& next_hop,
                   uint32_t metric,
                   uint64_t last_update,
                   const NodeId& destination_node) {
    return Route{
        .destination = destination,
        .destination_node = destination_node,
        .next_hop = next_hop,
        .metric = metric,
        .last_update = last_update,
    };
}

Route route_create(const NodeId& destination_node,
                   const NodeId& next_hop,
                   uint32_t metric,
                   uint64_t last_update) {
    return Route{
        .destination = {},
        .destination_node = destination_node,
        .next_hop = next_hop,
        .metric = metric,
        .last_update = last_update,
    };
}

bool route_equal(const Route& a, const Route& b) noexcept {
    return a == b;
}

} // namespace madoka
