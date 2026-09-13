#include "protocol/codec.hpp"

#include <cstring>

namespace madoka {

std::string_view to_string(MessageType type) noexcept {
    switch (type) {
        case MessageType::Hello:
            return "Hello";
        case MessageType::KeepAlive:
            return "KeepAlive";
        case MessageType::Data:
            return "Data";
        case MessageType::Control:
            return "Control";
        default:
            return "Unknown";
    }
}

bool message_validate(const Message& msg, std::string* error) {
    if (msg.version != PROTOCOL_VERSION) {
        if (error) {
            *error =
                "Unsupported protocol version: " + std::to_string(msg.version);
        }
        return false;
    }

    if (msg.type != MessageType::Hello && msg.type != MessageType::KeepAlive &&
        msg.type != MessageType::Data && msg.type != MessageType::Control) {
        if (error) {
            *error = "Unrecognized message type: " +
                     std::to_string(static_cast<uint8_t>(msg.type));
        }
        return false;
    }

    if (msg.payload.size() > MAX_PAYLOAD_SIZE) {
        if (error) {
            *error = "Message payload size (" +
                     std::to_string(msg.payload.size()) +
                     ") exceeds limit of " + std::to_string(MAX_PAYLOAD_SIZE) +
                     " bytes";
        }
        return false;
    }

    return true;
}

std::vector<uint8_t> message_encode(const Message& msg, std::string* error) {
    if (!message_validate(msg, error)) {
        return {};
    }

    const uint16_t length = static_cast<uint16_t>(msg.payload.size());
    std::vector<uint8_t> buffer;
    buffer.reserve(HEADER_SIZE + length);

    buffer.push_back(msg.version);
    buffer.push_back(static_cast<uint8_t>(msg.type));
    buffer.push_back(static_cast<uint8_t>((length >> 8) & 0xFF));
    buffer.push_back(static_cast<uint8_t>(length & 0xFF));

    buffer.insert(buffer.end(), msg.payload.begin(), msg.payload.end());
    return buffer;
}

bool message_decode(std::span<const uint8_t> bytes,
                    Message* out_msg,
                    std::string* error) {
    if (bytes.size() < HEADER_SIZE) {
        if (error) {
            *error = "Buffer too small for message header: " +
                     std::to_string(bytes.size()) + " bytes";
        }
        return false;
    }

    const uint8_t version = bytes[0];
    if (version != PROTOCOL_VERSION) {
        if (error) {
            *error = "Unsupported protocol version: " + std::to_string(version);
        }
        return false;
    }

    const uint8_t type_raw = bytes[1];
    if (type_raw != static_cast<uint8_t>(MessageType::Hello) &&
        type_raw != static_cast<uint8_t>(MessageType::KeepAlive) &&
        type_raw != static_cast<uint8_t>(MessageType::Data) &&
        type_raw != static_cast<uint8_t>(MessageType::Control)) {
        if (error) {
            *error = "Unrecognized message type: " + std::to_string(type_raw);
        }
        return false;
    }

    const uint16_t length = (static_cast<uint16_t>(bytes[2]) << 8) |
                            static_cast<uint16_t>(bytes[3]);
    if (length > MAX_PAYLOAD_SIZE) {
        if (error) {
            *error = "Declared message payload (" + std::to_string(length) +
                     ") exceeds maximum allowed payload of " +
                     std::to_string(MAX_PAYLOAD_SIZE) + " bytes";
        }
        return false;
    }

    if (bytes.size() < HEADER_SIZE + length) {
        if (error) {
            *error = "Incomplete message buffer: expected " +
                     std::to_string(HEADER_SIZE + length) +
                     " bytes, available " + std::to_string(bytes.size()) +
                     " bytes";
        }
        return false;
    }

    if (out_msg) {
        out_msg->version = version;
        out_msg->type = static_cast<MessageType>(type_raw);
        out_msg->payload.assign(bytes.begin() + HEADER_SIZE,
                                bytes.begin() + HEADER_SIZE + length);
    }
    return true;
}

std::optional<std::size_t> message_peek_size(std::span<const uint8_t> bytes,
                                             std::string* error) {
    if (bytes.size() < HEADER_SIZE) {
        return std::nullopt;
    }

    const uint8_t version = bytes[0];
    if (version != PROTOCOL_VERSION) {
        if (error) {
            *error = "Unsupported protocol version in peek: " +
                     std::to_string(version);
        }
        return std::nullopt;
    }

    const uint8_t type_raw = bytes[1];
    if (type_raw != static_cast<uint8_t>(MessageType::Hello) &&
        type_raw != static_cast<uint8_t>(MessageType::KeepAlive) &&
        type_raw != static_cast<uint8_t>(MessageType::Data) &&
        type_raw != static_cast<uint8_t>(MessageType::Control)) {
        if (error) {
            *error = "Unrecognized message type in peek: " +
                     std::to_string(type_raw);
        }
        return std::nullopt;
    }

    const uint16_t length = (static_cast<uint16_t>(bytes[2]) << 8) |
                            static_cast<uint16_t>(bytes[3]);
    if (length > MAX_PAYLOAD_SIZE) {
        if (error) {
            *error = "Declared message payload (" + std::to_string(length) +
                     ") exceeds maximum allowed payload of " +
                     std::to_string(MAX_PAYLOAD_SIZE) + " bytes";
        }
        return std::nullopt;
    }

    return HEADER_SIZE + length;
}

} // namespace madoka
