#include "network/control_message.hpp"

#include "network/serialization.hpp"

#include <mutex>

namespace madoka {

namespace {

std::mutex g_control_mutex;
std::function<void(Peer&, const ControlMessage&)> g_sender_hook{nullptr};
std::function<void(const ControlMessage&)> g_handler_hook{nullptr};

} // namespace

std::string_view to_string(ControlMessageType type) noexcept {
    switch (type) {
        case ControlMessageType::HELLO:
            return "HELLO";
        case ControlMessageType::NEIGHBOR_ADVERTISEMENT:
            return "NEIGHBOR_ADVERTISEMENT";
        case ControlMessageType::ROUTE_ADVERTISEMENT:
            return "ROUTE_ADVERTISEMENT";
        case ControlMessageType::JOIN_REQUEST:
            return "JOIN_REQUEST";
        case ControlMessageType::JOIN_RESPONSE:
            return "JOIN_RESPONSE";
        case ControlMessageType::FIND_NODE:
            return "FIND_NODE";
        case ControlMessageType::NEIGHBORS:
            return "NEIGHBORS";
        case ControlMessageType::NODE_ANNOUNCE:
            return "NODE_ANNOUNCE";
        case ControlMessageType::NODE_ANNOUNCE_ACK:
            return "NODE_ANNOUNCE_ACK";
        default:
            return "Invalid";
    }
}

ControlMessage control_message_create(ControlMessageType type,
                                      uint64_t sequence_number,
                                      const NodeId& sender,
                                      std::vector<uint8_t> payload) {
    return ControlMessage{
        .type = type,
        .sequence_number = sequence_number,
        .sender = sender,
        .payload = std::move(payload),
    };
}

bool control_message_validate(const ControlMessage& message,
                              std::string* error) {
    if (message.type != ControlMessageType::HELLO &&
        message.type != ControlMessageType::NEIGHBOR_ADVERTISEMENT &&
        message.type != ControlMessageType::ROUTE_ADVERTISEMENT &&
        message.type != ControlMessageType::JOIN_REQUEST &&
        message.type != ControlMessageType::JOIN_RESPONSE &&
        message.type != ControlMessageType::FIND_NODE &&
        message.type != ControlMessageType::NEIGHBORS &&
        message.type != ControlMessageType::NODE_ANNOUNCE &&
        message.type != ControlMessageType::NODE_ANNOUNCE_ACK) {
        if (error != nullptr) {
            *error = "Invalid control message type: " +
                     std::to_string(static_cast<uint8_t>(message.type));
        }
        return false;
    }

    constexpr std::size_t MAX_CONTROL_PAYLOAD = 65536;
    if (message.payload.size() > MAX_CONTROL_PAYLOAD) {
        if (error != nullptr) {
            *error = "Control message payload too large: " +
                     std::to_string(message.payload.size()) + " bytes";
        }
        return false;
    }

    return true;
}

void set_control_message_sender(
    std::function<void(Peer&, const ControlMessage&)> sender) {
    std::lock_guard<std::mutex> lock(g_control_mutex);
    g_sender_hook = std::move(sender);
}

void set_control_message_handler(
    std::function<void(const ControlMessage&)> handler) {
    std::lock_guard<std::mutex> lock(g_control_mutex);
    g_handler_hook = std::move(handler);
}

void send_control_message(Peer& peer, const ControlMessage& message) {
    if (peer.state != PeerState::Connected) {
        return;
    }

    if (!control_message_validate(message)) {
        return;
    }

    std::function<void(Peer&, const ControlMessage&)> sender_copy;
    {
        std::lock_guard<std::mutex> lock(g_control_mutex);
        sender_copy = g_sender_hook;
    }

    if (sender_copy) {
        sender_copy(peer, message);
    }
}

void handle_control_message(const ControlMessage& message) {
    if (!control_message_validate(message)) {
        return;
    }

    std::function<void(const ControlMessage&)> handler_copy;
    {
        std::lock_guard<std::mutex> lock(g_control_mutex);
        handler_copy = g_handler_hook;
    }

    if (handler_copy) {
        handler_copy(message);
    }
}

} // namespace madoka
