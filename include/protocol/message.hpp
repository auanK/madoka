#ifndef MADOKA_PROTOCOL_MESSAGE_HPP
#define MADOKA_PROTOCOL_MESSAGE_HPP

#include <cstdint>
#include <string_view>
#include <vector>

namespace madoka {

enum class MessageType : uint8_t {
    Hello = 1,
    KeepAlive = 2,
    Data = 3,
    Control = 4,

    HELLO = Hello,
    KEEPALIVE = KeepAlive,
    DATA = Data,
    CONTROL = Control
};

constexpr uint8_t PROTOCOL_VERSION = 1;

constexpr std::size_t HEADER_SIZE = 4;

constexpr std::size_t MAX_MESSAGE_SIZE = 4096;

constexpr std::size_t MAX_PAYLOAD_SIZE = MAX_MESSAGE_SIZE - HEADER_SIZE;

struct Message {
    uint8_t version{PROTOCOL_VERSION};
    MessageType type{MessageType::Hello};
    std::vector<uint8_t> payload{};

    bool operator==(const Message& other) const = default;
};

std::string_view to_string(MessageType type) noexcept;

} // namespace madoka

#endif
