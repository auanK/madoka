#include "network/data_serialization.hpp"

#include <algorithm>
#include <cstring>

namespace madoka {

namespace {

void write_u32_be(uint8_t* dst, uint32_t val) noexcept {
    dst[0] = static_cast<uint8_t>((val >> 24) & 0xFF);
    dst[1] = static_cast<uint8_t>((val >> 16) & 0xFF);
    dst[2] = static_cast<uint8_t>((val >> 8) & 0xFF);
    dst[3] = static_cast<uint8_t>(val & 0xFF);
}

uint32_t read_u32_be(const uint8_t* src) noexcept {
    return (static_cast<uint32_t>(src[0]) << 24) |
           (static_cast<uint32_t>(src[1]) << 16) |
           (static_cast<uint32_t>(src[2]) << 8) |
           (static_cast<uint32_t>(src[3]));
}

void write_u64_be(uint8_t* dst, uint64_t val) noexcept {
    dst[0] = static_cast<uint8_t>((val >> 56) & 0xFF);
    dst[1] = static_cast<uint8_t>((val >> 48) & 0xFF);
    dst[2] = static_cast<uint8_t>((val >> 40) & 0xFF);
    dst[3] = static_cast<uint8_t>((val >> 32) & 0xFF);
    dst[4] = static_cast<uint8_t>((val >> 24) & 0xFF);
    dst[5] = static_cast<uint8_t>((val >> 16) & 0xFF);
    dst[6] = static_cast<uint8_t>((val >> 8) & 0xFF);
    dst[7] = static_cast<uint8_t>(val & 0xFF);
}

uint64_t read_u64_be(const uint8_t* src) noexcept {
    return (static_cast<uint64_t>(src[0]) << 56) |
           (static_cast<uint64_t>(src[1]) << 48) |
           (static_cast<uint64_t>(src[2]) << 40) |
           (static_cast<uint64_t>(src[3]) << 32) |
           (static_cast<uint64_t>(src[4]) << 24) |
           (static_cast<uint64_t>(src[5]) << 16) |
           (static_cast<uint64_t>(src[6]) << 8) |
           (static_cast<uint64_t>(src[7]));
}

} // namespace

std::vector<uint8_t> serialize_packet(const DataPacket& packet) {
    const uint32_t payload_len = static_cast<uint32_t>(packet.payload.size());
    std::vector<uint8_t> buffer(DATA_PACKET_HEADER_SIZE + payload_len);

    buffer[0] = static_cast<uint8_t>(packet.type);
    std::memcpy(&buffer[1], packet.source.data(), packet.source.size());
    std::memcpy(
        &buffer[33], packet.destination.data(), packet.destination.size());
    write_u64_be(&buffer[65], packet.packet_id);
    buffer[73] = packet.ttl;
    buffer[74] = packet.requires_ack ? 1 : 0;
    write_u32_be(&buffer[75], packet.sequence_number);
    write_u32_be(&buffer[79], payload_len);

    if (payload_len > 0) {
        std::memcpy(&buffer[DATA_PACKET_HEADER_SIZE],
                    packet.payload.data(),
                    payload_len);
    }

    return buffer;
}

bool deserialize_packet(std::span<const uint8_t> data,
                        DataPacket* out_packet,
                        std::string* error) {
    if (!out_packet) {
        if (error) {
            *error = "Null destination pointer";
        }
        return false;
    }

    if (data.size() < DATA_PACKET_HEADER_SIZE) {
        if (error) {
            *error = "Buffer smaller than DataPacket header size";
        }
        return false;
    }

    const uint8_t type_raw = data[0];
    if (type_raw != static_cast<uint8_t>(PacketType::DATA) &&
        type_raw != static_cast<uint8_t>(PacketType::ACK)) {
        if (error) {
            *error = "Unrecognized PacketType";
        }
        return false;
    }

    const uint32_t payload_len = read_u32_be(&data[79]);
    if (payload_len > MAX_DATA_PAYLOAD_LIMIT) {
        if (error) {
            *error = "Payload length exceeds maximum allowed limit";
        }
        return false;
    }

    if (data.size() != DATA_PACKET_HEADER_SIZE + payload_len) {
        if (error) {
            *error = data.size() < DATA_PACKET_HEADER_SIZE + payload_len
                         ? "Truncated payload buffer"
                         : "Trailing bytes after DataPacket payload";
        }
        return false;
    }

    out_packet->type = static_cast<PacketType>(type_raw);
    std::memcpy(out_packet->source.data(), &data[1], 32);
    std::memcpy(out_packet->destination.data(), &data[33], 32);
    out_packet->packet_id = read_u64_be(&data[65]);
    out_packet->ttl = data[73];
    out_packet->requires_ack = (data[74] != 0);
    out_packet->sequence_number = read_u32_be(&data[75]);

    out_packet->payload.resize(payload_len);
    if (payload_len > 0) {
        std::memcpy(out_packet->payload.data(),
                    &data[DATA_PACKET_HEADER_SIZE],
                    payload_len);
    }

    return true;
}

DataPacket deserialize_packet(const std::vector<uint8_t>& data) {
    DataPacket packet{};
    packet.type = PacketType::Invalid;
    deserialize_packet(data, &packet);
    return packet;
}

} // namespace madoka
