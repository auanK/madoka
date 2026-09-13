#ifndef MADOKA_NETWORK_DATA_PACKET_HPP
#define MADOKA_NETWORK_DATA_PACKET_HPP

#include "core/config.hpp"

#include <cstdint>
#include <string_view>
#include <vector>

namespace madoka {

enum class PacketType : uint8_t {
    DATA = 0,
    ACK = 1,
    Invalid = 255
};

[[nodiscard]] std::string_view to_string(PacketType type) noexcept;

struct DataPacket {
    PacketType type{PacketType::DATA};

    NodeId source{};

    NodeId destination{};

    uint64_t packet_id{0};

    uint8_t ttl{64};

    bool requires_ack{false};

    uint32_t sequence_number{0};

    std::vector<uint8_t> payload{};

    [[nodiscard]] bool is_valid() const noexcept {
        return type == PacketType::DATA || type == PacketType::ACK;
    }

    bool operator==(const DataPacket& other) const = default;
};

DataPacket data_packet_create(PacketType type,
                              const NodeId& source,
                              const NodeId& destination,
                              uint64_t packet_id,
                              uint8_t ttl = 64,
                              std::vector<uint8_t> payload = {});

DataPacket data_packet_create(PacketType type,
                              const NodeId& source,
                              const NodeId& destination,
                              uint64_t packet_id,
                              uint8_t ttl,
                              bool requires_ack,
                              uint32_t sequence_number,
                              std::vector<uint8_t> payload = {});

bool data_packet_equal(const DataPacket& a, const DataPacket& b) noexcept;

} // namespace madoka

#endif
