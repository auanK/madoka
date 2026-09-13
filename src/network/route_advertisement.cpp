#include "network/route_advertisement.hpp"

namespace madoka {

RouteAdvertisement
route_create_advertisement(const NodeId& sender,
                           const RouteTable& table,
                           uint64_t sequence_number,
                           const std::optional<NodeId>& target_neighbor,
                           SplitHorizonMode mode,
                           uint64_t generation) {
    std::vector<Route> filtered_routes;
    filtered_routes.reserve(table.routes.size());

    for (const auto& r : table.routes) {
        if (target_neighbor.has_value() && r.next_hop == *target_neighbor) {
            if (mode == SplitHorizonMode::SplitHorizon) {
                continue;
            }
            if (mode == SplitHorizonMode::PoisonReverse) {
                Route poisoned = r;
                poisoned.metric = ROUTE_METRIC_INFINITY;
                filtered_routes.push_back(poisoned);
                continue;
            }
        }
        filtered_routes.push_back(r);
    }

    return RouteAdvertisement{
        .sender = sender,
        .generation = generation,
        .sequence_number = sequence_number,
        .routes = std::move(filtered_routes),
    };
}

bool validate_route_advertisement(const RouteAdvertisement& advertisement,
                                  const IPv6& network,
                                  std::string* error) {
    if (advertisement.sender == NodeId{} ||
        advertisement.routes.size() > MAX_ROUTE_TABLE_ENTRIES) {
        if (error) {
            *error = "Route advertisement sender or route count is invalid";
        }
        return false;
    }
    for (const auto& route : advertisement.routes) {
        if (route.destination_node == NodeId{}) {
            if (error) {
                *error = "Route advertisement destination Node ID is empty";
            }
            return false;
        }
        if (route.destination !=
            virtual_address(network, route.destination_node)) {
            if (error) {
                *error = "Route advertisement Node ID and IPv6 disagree";
            }
            return false;
        }
        if (route.metric > ROUTE_METRIC_INFINITY) {
            if (error) {
                *error = "Route advertisement metric exceeds infinity";
            }
            return false;
        }
    }
    return true;
}

} // namespace madoka
