#ifndef MADOKA_NETWORK_SERIALIZATION_HPP
#define MADOKA_NETWORK_SERIALIZATION_HPP

#include "network/control_message.hpp"
#include "network/discovery.hpp"
#include "network/heartbeat.hpp"
#include "network/join.hpp"
#include "network/route_advertisement.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace madoka {

constexpr std::size_t CONTROL_MESSAGE_HEADER_SIZE = 1 + 8 + 32 + 4;
constexpr std::size_t HELLO_MESSAGE_WIRE_SIZE = 32 + 8;
constexpr std::size_t NEIGHBOR_ADV_WIRE_SIZE = 32 + 16 + 8 + 8;
constexpr std::size_t ROUTE_ENTRY_WIRE_SIZE = 32 + 16 + 4;
constexpr std::size_t ROUTE_ADVERTISEMENT_HEADER_SIZE = 32 + 8 + 8 + 4;
constexpr std::size_t FIND_NODE_WIRE_SIZE = 32;
constexpr std::size_t NODE_ANNOUNCE_ACK_WIRE_SIZE = 1 + 32;

std::vector<uint8_t> serialize_control_message(const ControlMessage& message);

ControlMessage deserialize_control_message(const std::vector<uint8_t>& data);

bool deserialize_control_message(std::span<const uint8_t> data,
                                 ControlMessage* out_message,
                                 std::string* error = nullptr);

std::vector<uint8_t> serialize_hello_message(const HelloMessage& msg);

bool deserialize_hello_message(std::span<const uint8_t> data,
                               HelloMessage* out_msg,
                               std::string* error = nullptr);

HelloMessage deserialize_hello_message(const std::vector<uint8_t>& data);

std::vector<uint8_t>
serialize_neighbor_advertisement(const NeighborAdvertisement& adv);

bool deserialize_neighbor_advertisement(std::span<const uint8_t> data,
                                        NeighborAdvertisement* out_adv,
                                        std::string* error = nullptr);

NeighborAdvertisement
deserialize_neighbor_advertisement(const std::vector<uint8_t>& data);

std::vector<uint8_t>
serialize_route_advertisement(const RouteAdvertisement& adv);

bool deserialize_route_advertisement(std::span<const uint8_t> data,
                                     RouteAdvertisement* out_adv,
                                     std::string* error = nullptr);

RouteAdvertisement
deserialize_route_advertisement(const std::vector<uint8_t>& data);

std::vector<uint8_t> serialize_node_contact(const NodeContact& contact);

bool deserialize_node_contact(std::span<const uint8_t> data,
                              NodeContact* out_contact,
                              std::size_t* out_consumed = nullptr,
                              std::string* error = nullptr);

NodeContact deserialize_node_contact(const std::vector<uint8_t>& data);

std::vector<uint8_t> serialize_join_request(const JoinRequest& req);

bool deserialize_join_request(std::span<const uint8_t> data,
                              JoinRequest* out_req,
                              std::string* error = nullptr);

JoinRequest deserialize_join_request(const std::vector<uint8_t>& data);

std::vector<uint8_t> serialize_join_response(const JoinResponse& resp);

bool deserialize_join_response(std::span<const uint8_t> data,
                               JoinResponse* out_resp,
                               std::string* error = nullptr);

JoinResponse deserialize_join_response(const std::vector<uint8_t>& data);

std::vector<uint8_t> serialize_find_node(const FindNodeMessage& msg);

bool deserialize_find_node(std::span<const uint8_t> data,
                           FindNodeMessage* out_msg,
                           std::string* error = nullptr);

FindNodeMessage deserialize_find_node(const std::vector<uint8_t>& data);

std::vector<uint8_t> serialize_neighbors(const NeighborsMessage& msg);

bool deserialize_neighbors(std::span<const uint8_t> data,
                           NeighborsMessage* out_msg,
                           std::string* error = nullptr);

NeighborsMessage deserialize_neighbors(const std::vector<uint8_t>& data);

std::vector<uint8_t> serialize_node_announce(const NodeAnnounceMessage& msg);

bool deserialize_node_announce(std::span<const uint8_t> data,
                               NodeAnnounceMessage* out_msg,
                               std::string* error = nullptr);

NodeAnnounceMessage deserialize_node_announce(const std::vector<uint8_t>& data);

std::vector<uint8_t> serialize_node_announce_ack(const NodeAnnounceAck& msg);

bool deserialize_node_announce_ack(std::span<const uint8_t> data,
                                   NodeAnnounceAck* out_msg,
                                   std::string* error = nullptr);

NodeAnnounceAck deserialize_node_announce_ack(const std::vector<uint8_t>& data);

} // namespace madoka

#endif
