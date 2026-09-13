#ifndef MADOKA_NETWORK_CONTROL_MESSAGE_HPP
#define MADOKA_NETWORK_CONTROL_MESSAGE_HPP

#include "core/config.hpp"
#include "network/peer.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace madoka {

enum class ControlMessageType : uint8_t {
    Invalid = 0,
    HELLO = 1,
    NEIGHBOR_ADVERTISEMENT = 2,
    ROUTE_ADVERTISEMENT = 3,
    JOIN_REQUEST = 4,
    JOIN_RESPONSE = 5,
    FIND_NODE = 6,
    NEIGHBORS = 7,
    NODE_ANNOUNCE = 8,
    NODE_ANNOUNCE_ACK = 9
};

std::string_view to_string(ControlMessageType type) noexcept;

struct ControlMessage {
    ControlMessageType type{ControlMessageType::Invalid};

    uint64_t sequence_number{0};

    NodeId sender{};

    std::vector<uint8_t> payload{};

    [[nodiscard]] bool is_valid() const noexcept {
        return type != ControlMessageType::Invalid;
    }

    bool operator==(const ControlMessage& other) const = default;
};

ControlMessage control_message_create(ControlMessageType type,
                                      uint64_t sequence_number,
                                      const NodeId& sender,
                                      std::vector<uint8_t> payload = {});

bool control_message_validate(const ControlMessage& message,
                              std::string* error = nullptr);

void set_control_message_sender(
    std::function<void(Peer&, const ControlMessage&)> sender);

void set_control_message_handler(
    std::function<void(const ControlMessage&)> handler);

void send_control_message(Peer& peer, const ControlMessage& message);

void handle_control_message(const ControlMessage& message);

} // namespace madoka

#endif
