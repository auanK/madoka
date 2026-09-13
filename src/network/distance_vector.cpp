#include "network/distance_vector.hpp"

#include <algorithm>

namespace madoka {

namespace {

bool same_destination(const Route& left, const Route& right) noexcept {
    if (left.destination_node != NodeId{} &&
        right.destination_node != NodeId{}) {
        return left.destination_node == right.destination_node;
    }
    return left.destination == right.destination;
}

bool node_id_less(const NodeId& left, const NodeId& right) noexcept {
    return std::lexicographical_compare(
        left.begin(), left.end(), right.begin(), right.end());
}

bool apply_routes(RouteTable& table,
                  const NodeId& neighbor,
                  const RouteAdvertisement& advertisement,
                  uint64_t current_time,
                  uint32_t link_cost) {
    bool changed = false;
    const auto old_size = table.routes.size();
    std::erase_if(table.routes, [&](const Route& route) {
        if (route.next_hop != neighbor || route.destination_node == neighbor) {
            return false;
        }
        return std::none_of(advertisement.routes.begin(),
                            advertisement.routes.end(),
                            [&](const Route& advertised) {
                                return same_destination(route, advertised);
                            });
    });
    changed = table.routes.size() != old_size;

    for (const auto& advertised : advertisement.routes) {
        if (advertised.destination_node == neighbor) {
            continue;
        }
        const uint64_t candidate_metric =
            static_cast<uint64_t>(link_cost) + advertised.metric;
        const uint32_t metric = static_cast<uint32_t>(
            std::min<uint64_t>(ROUTE_METRIC_INFINITY, candidate_metric));
        auto existing = std::find_if(
            table.routes.begin(), table.routes.end(), [&](const Route& route) {
                return same_destination(route, advertised);
            });

        if (metric >= ROUTE_METRIC_INFINITY) {
            if (existing != table.routes.end() &&
                existing->next_hop == neighbor &&
                existing->metric != ROUTE_METRIC_INFINITY) {
                existing->metric = ROUTE_METRIC_INFINITY;
                existing->last_update = current_time;
                changed = true;
            }
            continue;
        }

        const Route candidate = route_create(advertised.destination,
                                             neighbor,
                                             metric,
                                             current_time,
                                             advertised.destination_node);
        if (existing == table.routes.end()) {
            if (table.routes.size() < MAX_ROUTE_TABLE_ENTRIES) {
                table.routes.push_back(candidate);
                changed = true;
            }
            continue;
        }

        const bool better_metric = metric < existing->metric;
        const bool deterministic_tie =
            metric == existing->metric &&
            node_id_less(neighbor, existing->next_hop);
        const bool refresh_same_neighbor = existing->next_hop == neighbor;
        if (better_metric || deterministic_tie || refresh_same_neighbor) {
            const bool route_changed =
                existing->destination != candidate.destination ||
                existing->destination_node != candidate.destination_node ||
                existing->next_hop != candidate.next_hop ||
                existing->metric != candidate.metric;
            if (route_changed) {
                *existing = candidate;
                changed = true;
            } else if (refresh_same_neighbor) {
                existing->last_update = current_time;
            }
        }
    }
    return changed;
}

} // namespace

bool distance_vector_update(RouteTable& table,
                            const NodeId& neighbor,
                            const RouteAdvertisement& advertisement,
                            uint64_t current_time,
                            uint32_t link_cost,
                            uint64_t* last_known_seq,
                            bool* routes_changed) {
    if (routes_changed != nullptr) {
        *routes_changed = false;
    }
    if (advertisement.sender != neighbor) {
        return false;
    }
    if (last_known_seq != nullptr) {
        if (advertisement.sequence_number <= *last_known_seq) {
            return false;
        }
        *last_known_seq = advertisement.sequence_number;
    }
    const bool changed =
        apply_routes(table, neighbor, advertisement, current_time, link_cost);
    if (routes_changed != nullptr) {
        *routes_changed = changed;
    }
    return true;
}

bool distance_vector_update(RouteTable& table,
                            const NodeId& neighbor,
                            const RouteAdvertisement& advertisement,
                            uint64_t current_time,
                            uint32_t link_cost,
                            RouteOriginStates* origin_states,
                            bool* routes_changed) {
    if (routes_changed != nullptr) {
        *routes_changed = false;
    }
    if (advertisement.sender != neighbor) {
        return false;
    }
    if (origin_states != nullptr) {
        const auto it = origin_states->find(advertisement.sender);
        if (it != origin_states->end()) {
            const auto& last = it->second;
            if (advertisement.generation < last.generation ||
                (advertisement.generation == last.generation &&
                 advertisement.sequence_number <= last.sequence)) {
                return false;
            }
        }
        (*origin_states)[advertisement.sender] =
            RouteOriginState{.generation = advertisement.generation,
                             .sequence = advertisement.sequence_number};
    }
    const bool changed =
        apply_routes(table, neighbor, advertisement, current_time, link_cost);
    if (routes_changed != nullptr) {
        *routes_changed = changed;
    }
    return true;
}

} // namespace madoka
