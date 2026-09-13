#include "network/data_packet.hpp"

#include <utility>

namespace madoka {

std::string_view to_string(PacketType type) noexcept {
    switch (type) {
        case PacketType::DATA:
            return "DATA";
        case PacketType::ACK:
            return "ACK";
        case PacketType::Invalid:
            return "Invalid";
    }
    return "Unknown";
}

DataPacket data_packet_create(PacketType type,
                              const NodeId& source,
                              const NodeId& destination,
                              uint64_t packet_id,
                              uint8_t ttl,
                              std::vector<uint8_t> payload) {
    return data_packet_create(type,
                              source,
                              destination,
                              packet_id,
                              ttl,
                              false,
                              0,
                              std::move(payload));
}

DataPacket data_packet_create(PacketType type,
                              const NodeId& source,
                              const NodeId& destination,
                              uint64_t packet_id,
                              uint8_t ttl,
                              bool requires_ack,
                              uint32_t sequence_number,
                              std::vector<uint8_t> payload) {
    DataPacket packet{};
    packet.type = type;
    packet.source = source;
    packet.destination = destination;
    packet.packet_id = packet_id;
    packet.ttl = ttl;
    packet.requires_ack = requires_ack;
    packet.sequence_number = sequence_number;
    packet.payload = std::move(payload);
    return packet;
}

bool data_packet_equal(const DataPacket& a, const DataPacket& b) noexcept {
    return a == b;
}

} // namespace madoka
