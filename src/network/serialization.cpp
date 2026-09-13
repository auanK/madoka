#include "network/serialization.hpp"

#include <algorithm>
#include <cstring>

namespace madoka {

namespace {

void write_u16_be(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
}

uint16_t read_u16_be(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) |
                                 static_cast<uint16_t>(p[1]));
}

void write_u32_be(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
}

uint32_t read_u32_be(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

void write_u64_be(std::vector<uint8_t>& buf, uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        buf.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
    }
}

uint64_t read_u64_be(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | static_cast<uint64_t>(p[i]);
    }
    return v;
}

constexpr std::size_t MAX_PAYLOAD_LIMIT = 65536;
constexpr std::size_t MAX_ROUTE_COUNT = MAX_ROUTE_TABLE_ENTRIES;
constexpr std::size_t MAX_CONTACT_ENDPOINT_SIZE = 255;

} // namespace

std::vector<uint8_t> serialize_control_message(const ControlMessage& message) {
    std::vector<uint8_t> buf;
    buf.reserve(CONTROL_MESSAGE_HEADER_SIZE + message.payload.size());

    buf.push_back(static_cast<uint8_t>(message.type));
    write_u64_be(buf, message.sequence_number);
    buf.insert(buf.end(), message.sender.begin(), message.sender.end());
    write_u32_be(buf, static_cast<uint32_t>(message.payload.size()));
    buf.insert(buf.end(), message.payload.begin(), message.payload.end());

    return buf;
}

bool deserialize_control_message(std::span<const uint8_t> data,
                                 ControlMessage* out_message,
                                 std::string* error) {
    if (data.size() < CONTROL_MESSAGE_HEADER_SIZE) {
        if (error != nullptr) {
            *error = "Buffer smaller than control message header";
        }
        return false;
    }

    const uint8_t type_raw = data[0];
    if (type_raw != static_cast<uint8_t>(ControlMessageType::HELLO) &&
        type_raw !=
            static_cast<uint8_t>(ControlMessageType::NEIGHBOR_ADVERTISEMENT) &&
        type_raw !=
            static_cast<uint8_t>(ControlMessageType::ROUTE_ADVERTISEMENT) &&
        type_raw != static_cast<uint8_t>(ControlMessageType::JOIN_REQUEST) &&
        type_raw != static_cast<uint8_t>(ControlMessageType::JOIN_RESPONSE) &&
        type_raw != static_cast<uint8_t>(ControlMessageType::FIND_NODE) &&
        type_raw != static_cast<uint8_t>(ControlMessageType::NEIGHBORS) &&
        type_raw != static_cast<uint8_t>(ControlMessageType::NODE_ANNOUNCE) &&
        type_raw !=
            static_cast<uint8_t>(ControlMessageType::NODE_ANNOUNCE_ACK)) {
        if (error != nullptr) {
            *error = "Unrecognized control message type: " +
                     std::to_string(type_raw);
        }
        return false;
    }

    const uint64_t seq = read_u64_be(data.data() + 1);

    NodeId sender{};
    std::copy_n(data.data() + 9, sender.size(), sender.begin());

    const uint32_t payload_len = read_u32_be(data.data() + 41);
    if (payload_len > MAX_PAYLOAD_LIMIT) {
        if (error != nullptr) {
            *error = "Payload declared length exceeds maximum allowed limit";
        }
        return false;
    }

    if (data.size() != CONTROL_MESSAGE_HEADER_SIZE + payload_len) {
        if (error != nullptr) {
            *error = "Buffer size mismatch with declared payload length";
        }
        return false;
    }

    if (out_message != nullptr) {
        out_message->type = static_cast<ControlMessageType>(type_raw);
        out_message->sequence_number = seq;
        out_message->sender = sender;
        out_message->payload.assign(data.data() + CONTROL_MESSAGE_HEADER_SIZE,
                                    data.data() + CONTROL_MESSAGE_HEADER_SIZE +
                                        payload_len);
    }

    return true;
}

ControlMessage deserialize_control_message(const std::vector<uint8_t>& data) {
    ControlMessage msg{};
    if (!deserialize_control_message(data, &msg)) {
        return ControlMessage{};
    }
    return msg;
}

std::vector<uint8_t> serialize_hello_message(const HelloMessage& msg) {
    std::vector<uint8_t> buf;
    buf.reserve(HELLO_MESSAGE_WIRE_SIZE);

    buf.insert(buf.end(), msg.sender.begin(), msg.sender.end());
    write_u64_be(buf, msg.timestamp);

    return buf;
}

bool deserialize_hello_message(std::span<const uint8_t> data,
                               HelloMessage* out_msg,
                               std::string* error) {
    if (data.size() != HELLO_MESSAGE_WIRE_SIZE) {
        if (error != nullptr) {
            *error = "Invalid hello message size";
        }
        return false;
    }

    if (out_msg != nullptr) {
        std::copy_n(
            data.data(), out_msg->sender.size(), out_msg->sender.begin());
        out_msg->timestamp = read_u64_be(data.data() + 32);
    }
    return true;
}

HelloMessage deserialize_hello_message(const std::vector<uint8_t>& data) {
    HelloMessage msg{};
    deserialize_hello_message(data, &msg);
    return msg;
}

std::vector<uint8_t>
serialize_neighbor_advertisement(const NeighborAdvertisement& adv) {
    std::vector<uint8_t> buf;
    buf.reserve(NEIGHBOR_ADV_WIRE_SIZE);

    buf.insert(buf.end(), adv.node_id.begin(), adv.node_id.end());
    buf.insert(buf.end(), adv.address.begin(), adv.address.end());
    write_u64_be(buf, adv.timestamp);
    write_u64_be(buf, adv.sequence_number);

    return buf;
}

bool deserialize_neighbor_advertisement(std::span<const uint8_t> data,
                                        NeighborAdvertisement* out_adv,
                                        std::string* error) {
    if (data.size() != NEIGHBOR_ADV_WIRE_SIZE) {
        if (error != nullptr) {
            *error = "Invalid neighbor advertisement size";
        }
        return false;
    }

    if (out_adv != nullptr) {
        std::copy_n(
            data.data(), out_adv->node_id.size(), out_adv->node_id.begin());
        std::copy_n(data.data() + 32,
                    out_adv->address.size(),
                    out_adv->address.begin());
        out_adv->timestamp = read_u64_be(data.data() + 48);
        out_adv->sequence_number = read_u64_be(data.data() + 56);
    }
    return true;
}

NeighborAdvertisement
deserialize_neighbor_advertisement(const std::vector<uint8_t>& data) {
    NeighborAdvertisement adv{};
    deserialize_neighbor_advertisement(data, &adv);
    return adv;
}

std::vector<uint8_t>
serialize_route_advertisement(const RouteAdvertisement& adv) {
    if (adv.routes.size() > MAX_ROUTE_COUNT) {
        return {};
    }
    std::vector<uint8_t> buf;
    buf.reserve(ROUTE_ADVERTISEMENT_HEADER_SIZE +
                adv.routes.size() * ROUTE_ENTRY_WIRE_SIZE);

    buf.insert(buf.end(), adv.sender.begin(), adv.sender.end());
    write_u64_be(buf, adv.generation);
    write_u64_be(buf, adv.sequence_number);
    write_u32_be(buf, static_cast<uint32_t>(adv.routes.size()));

    for (const auto& r : adv.routes) {
        buf.insert(
            buf.end(), r.destination_node.begin(), r.destination_node.end());
        buf.insert(buf.end(), r.destination.begin(), r.destination.end());
        write_u32_be(buf, r.metric);
    }

    return buf;
}

bool deserialize_route_advertisement(std::span<const uint8_t> data,
                                     RouteAdvertisement* out_adv,
                                     std::string* error) {
    if (data.size() < ROUTE_ADVERTISEMENT_HEADER_SIZE) {
        if (error != nullptr) {
            *error = "Buffer smaller than route advertisement header";
        }
        return false;
    }

    NodeId sender{};
    std::copy_n(data.data(), sender.size(), sender.begin());
    const uint64_t generation = read_u64_be(data.data() + 32);
    const uint64_t seq = read_u64_be(data.data() + 40);
    const uint32_t count = read_u32_be(data.data() + 48);

    if (count > MAX_ROUTE_COUNT) {
        if (error != nullptr) {
            *error = "Declared route count exceeds limit";
        }
        return false;
    }

    if (data.size() !=
        ROUTE_ADVERTISEMENT_HEADER_SIZE + count * ROUTE_ENTRY_WIRE_SIZE) {
        if (error != nullptr) {
            *error = "Buffer size does not match declared route count";
        }
        return false;
    }

    if (out_adv != nullptr) {
        out_adv->sender = sender;
        out_adv->generation = generation;
        out_adv->sequence_number = seq;
        out_adv->routes.clear();
        out_adv->routes.reserve(count);

        std::size_t offset = ROUTE_ADVERTISEMENT_HEADER_SIZE;
        for (std::size_t i = 0; i < count; ++i) {
            NodeId destination_node{};
            std::copy_n(data.data() + offset,
                        destination_node.size(),
                        destination_node.begin());
            offset += 32;

            IPv6 destination{};
            std::copy_n(
                data.data() + offset, destination.size(), destination.begin());
            offset += 16;

            const uint32_t metric = read_u32_be(data.data() + offset);
            offset += 4;

            out_adv->routes.push_back(route_create(
                destination, NodeId{}, metric, 0, destination_node));
        }
    }

    return true;
}

RouteAdvertisement
deserialize_route_advertisement(const std::vector<uint8_t>& data) {
    RouteAdvertisement adv{};
    deserialize_route_advertisement(data, &adv);
    return adv;
}

std::vector<uint8_t> serialize_node_contact(const NodeContact& contact) {
    if (contact.endpoint.size() > MAX_CONTACT_ENDPOINT_SIZE) {
        return {};
    }
    std::vector<uint8_t> buf;
    buf.reserve(32 + 32 + 16 + 2 + contact.endpoint.size() + 8 + 4 + 1);

    buf.insert(buf.end(), contact.id.begin(), contact.id.end());
    buf.insert(buf.end(), contact.public_key.begin(), contact.public_key.end());
    buf.insert(buf.end(),
               contact.virtual_address.begin(),
               contact.virtual_address.end());
    write_u16_be(buf, static_cast<uint16_t>(contact.endpoint.size()));
    buf.insert(buf.end(), contact.endpoint.begin(), contact.endpoint.end());
    write_u64_be(buf, contact.last_seen_ms);
    write_u32_be(buf, contact.rtt_ms);
    buf.push_back(contact.failed_pings);

    return buf;
}

bool deserialize_node_contact(std::span<const uint8_t> data,
                              NodeContact* out_contact,
                              std::size_t* out_consumed,
                              std::string* error) {
    constexpr std::size_t MIN_SIZE = 32 + 32 + 16 + 2 + 8 + 4 + 1;
    if (data.size() < MIN_SIZE) {
        if (error != nullptr) {
            *error = "Buffer smaller than minimum node contact size";
        }
        return false;
    }

    const uint16_t ep_len = read_u16_be(data.data() + 80);
    const std::size_t total_size = MIN_SIZE + ep_len;
    if (ep_len > MAX_CONTACT_ENDPOINT_SIZE || data.size() < total_size) {
        if (error != nullptr) {
            *error = "Incomplete node contact buffer";
        }
        return false;
    }

    if (out_contact != nullptr) {
        std::copy_n(
            data.data(), out_contact->id.size(), out_contact->id.begin());
        std::copy_n(data.data() + 32,
                    out_contact->public_key.size(),
                    out_contact->public_key.begin());
        std::copy_n(data.data() + 64,
                    out_contact->virtual_address.size(),
                    out_contact->virtual_address.begin());
        out_contact->endpoint.assign(
            reinterpret_cast<const char*>(data.data() + 82), ep_len);
        std::size_t offset = 82 + ep_len;
        out_contact->last_seen_ms = read_u64_be(data.data() + offset);
        offset += 8;
        out_contact->rtt_ms = read_u32_be(data.data() + offset);
        offset += 4;
        out_contact->failed_pings = data[offset];
    }

    if (out_consumed != nullptr) {
        *out_consumed = total_size;
    }
    return true;
}

NodeContact deserialize_node_contact(const std::vector<uint8_t>& data) {
    NodeContact c{};
    deserialize_node_contact(data, &c);
    return c;
}

std::vector<uint8_t> serialize_join_request(const JoinRequest& req) {
    if (req.endpoint.size() > 255 || req.invite_token.size() > 512) {
        return {};
    }
    std::vector<uint8_t> buf;
    buf.reserve(32 + 32 + 16 + 2 + req.endpoint.size() + 8 + 8 + 2 +
                req.invite_token.size());

    buf.insert(buf.end(), req.node_id.begin(), req.node_id.end());
    buf.insert(buf.end(), req.public_key.begin(), req.public_key.end());
    buf.insert(
        buf.end(), req.virtual_address.begin(), req.virtual_address.end());
    write_u16_be(buf, static_cast<uint16_t>(req.endpoint.size()));
    buf.insert(buf.end(), req.endpoint.begin(), req.endpoint.end());
    write_u64_be(buf, req.timestamp);
    write_u64_be(buf, req.nonce);
    write_u16_be(buf, static_cast<uint16_t>(req.invite_token.size()));
    buf.insert(buf.end(), req.invite_token.begin(), req.invite_token.end());

    return buf;
}

bool deserialize_join_request(std::span<const uint8_t> data,
                              JoinRequest* out_req,
                              std::string* error) {
    constexpr std::size_t MIN_SIZE = 32 + 32 + 16 + 2 + 8 + 8 + 2;
    if (data.size() < MIN_SIZE) {
        if (error != nullptr) {
            *error = "Buffer smaller than minimum join request size";
        }
        return false;
    }

    const uint16_t ep_len = read_u16_be(data.data() + 80);
    if (ep_len > 255 || data.size() < MIN_SIZE + ep_len) {
        if (error != nullptr) {
            *error = "Invalid join endpoint length";
        }
        return false;
    }
    const std::size_t token_size_offset = 82 + ep_len + 8 + 8;
    const uint16_t token_len = read_u16_be(data.data() + token_size_offset);
    const std::size_t total_size = MIN_SIZE + ep_len + token_len;
    if (token_len > 512 || data.size() != total_size) {
        if (error != nullptr) {
            *error = "Join request buffer size mismatch";
        }
        return false;
    }

    if (out_req != nullptr) {
        std::copy_n(
            data.data(), out_req->node_id.size(), out_req->node_id.begin());
        std::copy_n(data.data() + 32,
                    out_req->public_key.size(),
                    out_req->public_key.begin());
        std::copy_n(data.data() + 64,
                    out_req->virtual_address.size(),
                    out_req->virtual_address.begin());
        out_req->endpoint.assign(
            reinterpret_cast<const char*>(data.data() + 82), ep_len);
        std::size_t offset = 82 + ep_len;
        out_req->timestamp = read_u64_be(data.data() + offset);
        offset += 8;
        out_req->nonce = read_u64_be(data.data() + offset);
        offset += 8;
        offset += 2;
        out_req->invite_token.assign(
            reinterpret_cast<const char*>(data.data() + offset), token_len);
    }
    return true;
}

JoinRequest deserialize_join_request(const std::vector<uint8_t>& data) {
    JoinRequest req{};
    deserialize_join_request(data, &req);
    return req;
}

std::vector<uint8_t> serialize_join_response(const JoinResponse& resp) {
    if (resp.peers.size() > KADEMLIA_K) {
        return {};
    }
    NodeContact boot = resp.bootstrap_contact;
    if (boot.id == NodeId{}) {
        boot.id = resp.bootstrap_id;
    }
    std::vector<uint8_t> buf;
    buf.reserve(1 + 100 + 2 + resp.peers.size() * 100);

    buf.push_back(resp.accepted ? 1 : 0);
    auto boot_bytes = serialize_node_contact(boot);
    if (boot_bytes.empty()) {
        return {};
    }
    buf.insert(buf.end(), boot_bytes.begin(), boot_bytes.end());

    write_u16_be(buf, static_cast<uint16_t>(resp.peers.size()));

    for (const auto& peer : resp.peers) {
        auto contact_bytes = serialize_node_contact(peer);
        if (contact_bytes.empty()) {
            return {};
        }
        buf.insert(buf.end(), contact_bytes.begin(), contact_bytes.end());
    }

    return buf;
}

namespace {

bool deserialize_full_join_response(std::span<const uint8_t> data,
                                    JoinResponse* out_resp,
                                    std::string* error) {
    if (data.empty()) {
        if (error != nullptr) {
            *error = "Empty buffer for join response";
        }
        return false;
    }

    const bool accepted = (data[0] != 0);
    std::size_t offset = 1;

    NodeContact bootstrap_contact{};
    std::size_t boot_consumed = 0;
    if (!deserialize_node_contact(
            data.subspan(offset), &bootstrap_contact, &boot_consumed, error)) {
        return false;
    }
    offset += boot_consumed;

    if (data.size() < offset + 2) {
        if (error != nullptr) {
            *error = "Buffer smaller than join response peer count";
        }
        return false;
    }

    const uint16_t count = read_u16_be(data.data() + offset);
    offset += 2;

    if (count > KADEMLIA_K) {
        if (error != nullptr) {
            *error = "Join response peer count exceeds limit";
        }
        return false;
    }

    std::vector<NodeContact> peers;
    peers.reserve(count);

    for (std::size_t i = 0; i < count; ++i) {
        if (offset >= data.size()) {
            if (error != nullptr) {
                *error = "Truncated join response peers";
            }
            return false;
        }

        NodeContact contact{};
        std::size_t consumed = 0;
        if (!deserialize_node_contact(
                data.subspan(offset), &contact, &consumed, error)) {
            return false;
        }
        peers.push_back(std::move(contact));
        offset += consumed;
    }

    if (offset != data.size()) {
        if (error != nullptr) {
            *error = "Extraneous data in join response";
        }
        return false;
    }

    if (out_resp != nullptr) {
        out_resp->accepted = accepted;
        out_resp->bootstrap_id = bootstrap_contact.id;
        out_resp->bootstrap_contact = std::move(bootstrap_contact);
        out_resp->peers = std::move(peers);
    }
    return true;
}

} // namespace

bool deserialize_join_response(std::span<const uint8_t> data,
                               JoinResponse* out_resp,
                               std::string* error) {
    return deserialize_full_join_response(data, out_resp, error);
}

JoinResponse deserialize_join_response(const std::vector<uint8_t>& data) {
    JoinResponse resp{};
    deserialize_join_response(data, &resp);
    return resp;
}

std::vector<uint8_t> serialize_find_node(const FindNodeMessage& msg) {
    std::vector<uint8_t> buf(msg.target.begin(), msg.target.end());
    return buf;
}

bool deserialize_find_node(std::span<const uint8_t> data,
                           FindNodeMessage* out_msg,
                           std::string* error) {
    if (data.size() != FIND_NODE_WIRE_SIZE) {
        if (error != nullptr) {
            *error = "Invalid find node message size";
        }
        return false;
    }

    if (out_msg != nullptr) {
        std::copy_n(
            data.data(), out_msg->target.size(), out_msg->target.begin());
    }
    return true;
}

FindNodeMessage deserialize_find_node(const std::vector<uint8_t>& data) {
    FindNodeMessage msg{};
    deserialize_find_node(data, &msg);
    return msg;
}

std::vector<uint8_t> serialize_neighbors(const NeighborsMessage& msg) {
    if (msg.peers.size() > KADEMLIA_K) {
        return {};
    }
    std::vector<uint8_t> buf;
    buf.reserve(2 + msg.peers.size() * 100);

    write_u16_be(buf, static_cast<uint16_t>(msg.peers.size()));
    for (const auto& peer : msg.peers) {
        auto contact_bytes = serialize_node_contact(peer);
        if (contact_bytes.empty()) {
            return {};
        }
        buf.insert(buf.end(), contact_bytes.begin(), contact_bytes.end());
    }
    return buf;
}

bool deserialize_neighbors(std::span<const uint8_t> data,
                           NeighborsMessage* out_msg,
                           std::string* error) {
    if (data.size() < 2) {
        if (error != nullptr) {
            *error = "Buffer smaller than neighbors header";
        }
        return false;
    }

    const uint16_t count = read_u16_be(data.data());
    if (count > KADEMLIA_K) {
        if (error != nullptr) {
            *error = "Neighbors peer count exceeds limit";
        }
        return false;
    }
    std::vector<NodeContact> peers;
    peers.reserve(count);

    std::size_t offset = 2;
    for (std::size_t i = 0; i < count; ++i) {
        if (offset >= data.size()) {
            if (error != nullptr) {
                *error = "Truncated neighbors peer data";
            }
            return false;
        }

        NodeContact contact{};
        std::size_t consumed = 0;
        if (!deserialize_node_contact(
                data.subspan(offset), &contact, &consumed, error)) {
            return false;
        }
        peers.push_back(std::move(contact));
        offset += consumed;
    }

    if (offset != data.size()) {
        if (error != nullptr) {
            *error = "Extraneous bytes in neighbors message";
        }
        return false;
    }

    if (out_msg != nullptr) {
        out_msg->peers = std::move(peers);
    }
    return true;
}

NeighborsMessage deserialize_neighbors(const std::vector<uint8_t>& data) {
    NeighborsMessage msg{};
    deserialize_neighbors(data, &msg);
    return msg;
}

std::vector<uint8_t> serialize_node_announce(const NodeAnnounceMessage& msg) {
    std::vector<uint8_t> buf = serialize_node_contact(msg.contact);
    write_u64_be(buf, msg.nonce);
    return buf;
}

bool deserialize_node_announce(std::span<const uint8_t> data,
                               NodeAnnounceMessage* out_msg,
                               std::string* error) {
    if (data.size() < 8) {
        if (error != nullptr) {
            *error = "Buffer too small for node announce";
        }
        return false;
    }

    std::span<const uint8_t> contact_slice = data.first(data.size() - 8);
    NodeContact contact{};
    std::size_t consumed = 0;
    if (!deserialize_node_contact(contact_slice, &contact, &consumed, error)) {
        return false;
    }
    if (consumed != contact_slice.size()) {
        if (error != nullptr) {
            *error = "Node announce contact size mismatch";
        }
        return false;
    }

    const uint64_t nonce = read_u64_be(data.data() + (data.size() - 8));

    if (out_msg != nullptr) {
        out_msg->contact = std::move(contact);
        out_msg->nonce = nonce;
    }
    return true;
}

NodeAnnounceMessage
deserialize_node_announce(const std::vector<uint8_t>& data) {
    NodeAnnounceMessage msg{};
    deserialize_node_announce(data, &msg);
    return msg;
}

std::vector<uint8_t> serialize_node_announce_ack(const NodeAnnounceAck& msg) {
    std::vector<uint8_t> buf;
    buf.reserve(NODE_ANNOUNCE_ACK_WIRE_SIZE);
    buf.push_back(msg.accepted ? 1 : 0);
    buf.insert(buf.end(), msg.responder.begin(), msg.responder.end());
    return buf;
}

bool deserialize_node_announce_ack(std::span<const uint8_t> data,
                                   NodeAnnounceAck* out_msg,
                                   std::string* error) {
    if (data.size() != NODE_ANNOUNCE_ACK_WIRE_SIZE) {
        if (error != nullptr) {
            *error = "Invalid node announce ack size";
        }
        return false;
    }

    if (out_msg != nullptr) {
        out_msg->accepted = (data[0] != 0);
        std::copy_n(data.data() + 1,
                    out_msg->responder.size(),
                    out_msg->responder.begin());
    }
    return true;
}

NodeAnnounceAck
deserialize_node_announce_ack(const std::vector<uint8_t>& data) {
    NodeAnnounceAck msg{};
    deserialize_node_announce_ack(data, &msg);
    return msg;
}

} // namespace madoka
