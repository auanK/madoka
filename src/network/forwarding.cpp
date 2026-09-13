#include "network/forwarding.hpp"

namespace madoka {

ForwardingState forwarding_init(RoutingTable* table,
                                const NodeId* local_node_id) {
    ForwardingState state{.table = table};
    if (local_node_id != nullptr) {
        state.local_id = *local_node_id;
        state.has_local_id = true;
    }
    return state;
}

namespace {

void forward_impl(ForwardingState* state,
                  DataPacket* packet,
                  bool decrement_ttl) {
    if (state == nullptr || state->table == nullptr || packet == nullptr) {
        return;
    }
    if (state->has_local_id && packet->destination == state->local_id) {
        state->last_action = ForwardAction::DeliverLocally;
        state->last_next_hop = {};
        if (state->local_delivery_handler) {
            state->local_delivery_handler(*packet);
        }
        return;
    }

    if (decrement_ttl && packet->ttl <= 1) {
        packet->ttl = 0;
        state->metrics.ttl_expired_packets++;
        state->metrics.dropped_packets++;
        state->last_action = ForwardAction::DropTtlExpired;

        if (state->drop_handler) {
            state->drop_handler(*packet, "TTL expired");
        }
        return;
    }

    if (decrement_ttl) {
        packet->ttl--;
    }

    auto route_opt = routing_lookup(*state->table, packet->destination);
    if (!route_opt.has_value() || !route_opt->valid ||
        route_opt->metric >= ROUTE_METRIC_INFINITY) {
        state->metrics.unknown_destination_packets++;
        state->metrics.dropped_packets++;
        state->last_action = ForwardAction::DropNoRoute;
        state->last_next_hop = {};

        if (state->drop_handler) {
            state->drop_handler(*packet, "No route to destination");
        }
        return;
    }

    state->last_action = ForwardAction::ForwardToPeer;
    state->last_next_hop = route_opt->next_hop;
    state->metrics.forwarded_packets++;

    if (state->transmit_handler) {
        state->transmit_handler(route_opt->next_hop, *packet);
    }
}

} // namespace

void forwarding_forward(ForwardingState* state, DataPacket* packet) {
    forward_impl(state, packet, true);
}

void forwarding_forward_origin(ForwardingState* state, DataPacket* packet) {
    forward_impl(state, packet, false);
}

void forwarding_set_transmit_handler(ForwardingState* state,
                                     TransmitHandler handler) {
    if (state != nullptr) {
        state->transmit_handler = std::move(handler);
    }
}

void forwarding_set_local_delivery_handler(ForwardingState* state,
                                           LocalDeliveryHandler handler) {
    if (state != nullptr) {
        state->local_delivery_handler = std::move(handler);
    }
}

void forwarding_set_drop_handler(ForwardingState* state, DropHandler handler) {
    if (state != nullptr) {
        state->drop_handler = std::move(handler);
    }
}

} // namespace madoka
