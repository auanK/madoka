#ifndef MADOKA_NETWORK_JOIN_HPP
#define MADOKA_NETWORK_JOIN_HPP

#include "core/config.hpp"
#include "network/kademlia.hpp"

#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace madoka {

struct JoinRequest {
    NodeId node_id{};

    std::array<uint8_t, 32> public_key{};

    IPv6 virtual_address{};

    std::string endpoint{};

    uint64_t timestamp{0};

    uint64_t nonce{0};

    std::string invite_token{};

    bool operator==(const JoinRequest& other) const = default;
};

struct JoinResponse {
    bool accepted{false};

    NodeContact bootstrap_contact{};

    NodeId bootstrap_id{};

    std::vector<NodeContact> peers{};

    bool operator==(const JoinResponse& other) const {
        NodeContact left = bootstrap_contact;
        NodeContact right = other.bootstrap_contact;
        if (left.id == NodeId{}) {
            left.id = bootstrap_id;
        }
        if (right.id == NodeId{}) {
            right.id = other.bootstrap_id;
        }
        return accepted == other.accepted && left == right &&
               peers == other.peers;
    }
};

struct FindNodeMessage {
    NodeId target{};

    bool operator==(const FindNodeMessage& other) const = default;
};

struct NeighborsMessage {
    std::vector<NodeContact> peers{};

    bool operator==(const NeighborsMessage& other) const = default;
};

struct NodeAnnounceMessage {
    NodeContact contact{};
    uint64_t nonce{0};

    bool operator==(const NodeAnnounceMessage& other) const = default;
};

struct NodeAnnounceAck {
    bool accepted{false};
    NodeId responder{};

    bool operator==(const NodeAnnounceAck& other) const = default;
};

bool process_join_request(KademliaTable& table,
                          const JoinRequest& request,
                          JoinResponse& response,
                          const NodeContact* local_contact = nullptr);

bool handle_join_response(KademliaTable& table,
                          const JoinResponse& response,
                          const NodeContact& bootstrap_fallback = {});

void handle_find_node(const KademliaTable& table,
                      const FindNodeMessage& request,
                      NeighborsMessage& out_response);

void handle_neighbors(KademliaTable& table, const NeighborsMessage& message);

bool handle_node_announce(KademliaTable& table,
                          const NodeAnnounceMessage& announce,
                          NodeAnnounceAck& out_ack);

struct ControlMessage;

bool dispatch_join_protocol_message(KademliaTable& table,
                                    const ControlMessage& incoming,
                                    ControlMessage* out_reply,
                                    const NodeContact* local_contact = nullptr,
                                    bool join_admitted = false);

void kademlia_self_lookup(
    KademliaTable& table,
    std::function<std::vector<NodeContact>(const NodeId& peer,
                                           const NodeId& target)> query_fn,
    std::size_t alpha = 3);

} // namespace madoka

#endif
