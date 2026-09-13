#ifndef MADOKA_NETWORK_FORWARDING_HPP
#define MADOKA_NETWORK_FORWARDING_HPP

#include "core/config.hpp"
#include "metrics.hpp"
#include "network/data_packet.hpp"
#include "network/routing.hpp"

#include <cstdint>
#include <functional>
#include <string_view>

namespace madoka {

enum class ForwardAction : uint8_t {
    DeliverLocally = 0,
    ForwardToPeer = 1,
    DropNoRoute = 2,
    DropInvalid = 3,
    DropTtlExpired = 4
};

using TransmitHandler =
    std::function<void(const NodeId& next_hop, const DataPacket& packet)>;
using LocalDeliveryHandler = std::function<void(const DataPacket& packet)>;
using DropHandler =
    std::function<void(const DataPacket& packet, std::string_view reason)>;

struct ForwardingState {
    RoutingTable* table{nullptr};
    NodeId local_id{};
    bool has_local_id{false};
    ForwardingMetrics metrics{};
    ForwardAction last_action{ForwardAction::DropInvalid};
    NodeId last_next_hop{};
    TransmitHandler transmit_handler{nullptr};
    LocalDeliveryHandler local_delivery_handler{nullptr};
    DropHandler drop_handler{nullptr};
};

ForwardingState forwarding_init(RoutingTable* table,
                                const NodeId* local_node_id = nullptr);

void forwarding_forward(ForwardingState* state, DataPacket* packet);

void forwarding_forward_origin(ForwardingState* state, DataPacket* packet);

void forwarding_set_transmit_handler(ForwardingState* state,
                                     TransmitHandler handler);

void forwarding_set_local_delivery_handler(ForwardingState* state,
                                           LocalDeliveryHandler handler);

void forwarding_set_drop_handler(ForwardingState* state, DropHandler handler);

} // namespace madoka

#endif
