#ifndef MADOKA_NETWORK_DATA_SERIALIZATION_HPP
#define MADOKA_NETWORK_DATA_SERIALIZATION_HPP

#include "network/data_packet.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace madoka {

constexpr std::size_t DATA_PACKET_HEADER_SIZE = 1 + 32 + 32 + 8 + 1 + 1 + 4 + 4;

constexpr std::size_t MAX_DATA_PAYLOAD_LIMIT = 65536;

std::vector<uint8_t> serialize_packet(const DataPacket& packet);

bool deserialize_packet(std::span<const uint8_t> data,
                        DataPacket* out_packet,
                        std::string* error = nullptr);

DataPacket deserialize_packet(const std::vector<uint8_t>& data);

} // namespace madoka

#endif
