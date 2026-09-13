#include "network/routing.hpp"

#include <algorithm>

namespace madoka {

namespace {

bool is_non_empty_node(const NodeId& id) noexcept {
    static constexpr NodeId empty_id{};
    return id != empty_id;
}

bool node_id_less(const NodeId& left, const NodeId& right) noexcept {
    return std::lexicographical_compare(
        left.begin(), left.end(), right.begin(), right.end());
}

} // namespace

std::optional<RouteEntry> routing_lookup(const RouteTable& table,
                                         const NodeId& destination) {
    for (const auto& r : table.routes) {
        if (r.destination_node == destination) {
            return RouteEntry{
                .destination = destination,
                .next_hop = r.next_hop,
                .metric = r.metric,
                .valid = (r.metric < ROUTE_METRIC_INFINITY),
            };
        }
    }
    return std::nullopt;
}

RouteTable routing_init() {
    RouteTable table{};
    table.routes.reserve(MAX_ROUTE_TABLE_ENTRIES);
    return table;
}

bool routing_add_route(RouteTable& table, const Route& route) {
    for (auto& existing : table.routes) {
        bool match = false;
        if (is_non_empty_node(route.destination_node) &&
            is_non_empty_node(existing.destination_node)) {
            match = (existing.destination_node == route.destination_node);
        } else {
            match = (existing.destination == route.destination);
        }

        if (match) {
            const bool better = route.metric < existing.metric;
            const bool equal_but_deterministic =
                route.metric == existing.metric &&
                node_id_less(route.next_hop, existing.next_hop);
            if (better || equal_but_deterministic) {
                existing.destination = route.destination;
                existing.next_hop = route.next_hop;
                existing.metric = route.metric;
                existing.last_update = route.last_update;
                existing.destination_node = route.destination_node;
                return true;
            }

            return false;
        }
    }

    if (table.routes.size() >= MAX_ROUTE_TABLE_ENTRIES) {
        return false;
    }
    table.routes.push_back(route);
    return true;
}

const Route* routing_find_route(const RouteTable& table,
                                const IPv6& destination) {
    for (const auto& r : table.routes) {
        if (r.destination == destination) {
            return &r;
        }
    }
    return nullptr;
}

Route* routing_find_route(RouteTable& table, const IPv6& destination) {
    for (auto& r : table.routes) {
        if (r.destination == destination) {
            return &r;
        }
    }
    return nullptr;
}

const Route* routing_find_route(const RouteTable& table,
                                const NodeId& destination) {
    for (const auto& r : table.routes) {
        if (r.destination_node == destination) {
            return &r;
        }
    }
    return nullptr;
}

Route* routing_find_route(RouteTable& table, const NodeId& destination) {
    for (auto& r : table.routes) {
        if (r.destination_node == destination) {
            return &r;
        }
    }
    return nullptr;
}

bool routing_remove_route(RouteTable& table, const IPv6& destination) {
    auto it = std::find_if(table.routes.begin(),
                           table.routes.end(),
                           [&destination](const Route& r) {
                               return r.destination == destination;
                           });

    if (it != table.routes.end()) {
        table.routes.erase(it);
        return true;
    }
    return false;
}

bool routing_remove_route(RouteTable& table, const NodeId& destination) {
    auto it = std::find_if(table.routes.begin(),
                           table.routes.end(),
                           [&destination](const Route& r) {
                               return r.destination_node == destination;
                           });

    if (it != table.routes.end()) {
        table.routes.erase(it);
        return true;
    }
    return false;
}

void routing_clear(RouteTable& table) {
    table.routes.clear();
}

std::size_t routing_count(const RouteTable& table) noexcept {
    return table.routes.size();
}

void routing_expire_routes(RouteTable& table,
                           uint64_t current_time,
                           uint64_t timeout) {
    table.routes.erase(std::remove_if(table.routes.begin(),
                                      table.routes.end(),
                                      [current_time, timeout](const Route& r) {
                                          return current_time > r.last_update &&
                                                 (current_time -
                                                  r.last_update) > timeout;
                                      }),
                       table.routes.end());
}

} // namespace madoka
