#ifndef MADOKA_NETWORK_ROUTE_HPP
#define MADOKA_NETWORK_ROUTE_HPP

#include "core/config.hpp"

#include <cstdint>

namespace madoka {

constexpr uint32_t ROUTE_METRIC_INFINITY = 16;

struct Route {
    IPv6 destination{};

    NodeId destination_node{};

    NodeId next_hop{};

    uint32_t metric{0};

    uint64_t last_update{0};

    bool operator==(const Route& other) const = default;
};

Route route_create(const IPv6& destination,
                   const NodeId& next_hop,
                   uint32_t metric = 1,
                   uint64_t last_update = 0,
                   const NodeId& destination_node = {});

Route route_create(const NodeId& destination_node,
                   const NodeId& next_hop,
                   uint32_t metric = 1,
                   uint64_t last_update = 0);

bool route_equal(const Route& a, const Route& b) noexcept;

} // namespace madoka

#endif
