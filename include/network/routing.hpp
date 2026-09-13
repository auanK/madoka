#ifndef MADOKA_NETWORK_ROUTING_HPP
#define MADOKA_NETWORK_ROUTING_HPP

#include "network/route.hpp"

#include <cstddef>
#include <optional>
#include <vector>

namespace madoka {

constexpr std::size_t MAX_ROUTE_TABLE_ENTRIES = 16;

constexpr uint64_t ROUTE_ADVERTISEMENT_TIMEOUT_MS = 6000;

constexpr uint64_t ROUTE_TIMEOUT = 60;

struct RouteEntry {
    NodeId destination{};
    NodeId next_hop{};
    uint32_t metric{0};
    bool valid{false};

    bool operator==(const RouteEntry& other) const = default;
};

struct RouteTable;
using RoutingTable = RouteTable;

struct RouteTable {
    std::vector<Route> routes{};
};

RouteTable routing_init();

bool routing_add_route(RouteTable& table, const Route& route);

const Route* routing_find_route(const RouteTable& table,
                                const IPv6& destination);
Route* routing_find_route(RouteTable& table, const IPv6& destination);

const Route* routing_find_route(const RouteTable& table,
                                const NodeId& destination);
Route* routing_find_route(RouteTable& table, const NodeId& destination);

std::optional<RouteEntry> routing_lookup(const RouteTable& table,
                                         const NodeId& destination);

bool routing_remove_route(RouteTable& table, const IPv6& destination);

bool routing_remove_route(RouteTable& table, const NodeId& destination);

void routing_clear(RouteTable& table);

std::size_t routing_count(const RouteTable& table) noexcept;

void routing_expire_routes(RouteTable& table,
                           uint64_t current_time,
                           uint64_t timeout = ROUTE_TIMEOUT);

} // namespace madoka

#endif
