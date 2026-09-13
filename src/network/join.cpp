#include "network/join.hpp"

#include "network/control_message.hpp"
#include "network/serialization.hpp"

#include <openssl/evp.h>
#include <unordered_set>

namespace madoka {

bool process_join_request(KademliaTable& table,
                          const JoinRequest& request,
                          JoinResponse& response,
                          const NodeContact* local_contact) {
    NodeId derived_id{};
    std::size_t digest_len = derived_id.size();
    if (EVP_Q_digest(nullptr,
                     "SHA256",
                     nullptr,
                     request.public_key.data(),
                     request.public_key.size(),
                     derived_id.data(),
                     &digest_len) != 1 ||
        digest_len != derived_id.size() || derived_id != request.node_id) {
        response.accepted = false;
        if (local_contact != nullptr) {
            response.bootstrap_contact = *local_contact;
            response.bootstrap_id = local_contact->id;
        } else {
            response.bootstrap_contact = NodeContact{.id = table.local_id};
            response.bootstrap_id = table.local_id;
        }
        response.peers.clear();
        return false;
    }

    NodeContact contact{
        .id = request.node_id,
        .public_key = request.public_key,
        .virtual_address = request.virtual_address,
        .endpoint = request.endpoint,
        .last_seen_ms = request.timestamp,
        .rtt_ms = 0,
        .failed_pings = 0,
    };
    kademlia_insert(table, contact);

    response.accepted = true;
    if (local_contact != nullptr) {
        response.bootstrap_contact = *local_contact;
        response.bootstrap_id = local_contact->id;
    } else {
        response.bootstrap_contact = NodeContact{.id = table.local_id};
        response.bootstrap_id = table.local_id;
    }
    response.peers = kademlia_find_closest(table, request.node_id, KADEMLIA_K);
    return true;
}

bool handle_join_response(KademliaTable& table,
                          const JoinResponse& response,
                          const NodeContact& bootstrap_fallback) {
    if (!response.accepted) {
        return false;
    }

    NodeContact actual_boot = response.bootstrap_contact;
    if (actual_boot.id == NodeId{}) {
        actual_boot.id = response.bootstrap_id;
    }
    if (actual_boot.endpoint.empty() && !bootstrap_fallback.endpoint.empty()) {
        actual_boot.endpoint = bootstrap_fallback.endpoint;
    }
    if (actual_boot.public_key == std::array<uint8_t, 32>{} &&
        bootstrap_fallback.public_key != std::array<uint8_t, 32>{}) {
        actual_boot.public_key = bootstrap_fallback.public_key;
    }
    if (actual_boot.virtual_address == IPv6{} &&
        bootstrap_fallback.virtual_address != IPv6{}) {
        actual_boot.virtual_address = bootstrap_fallback.virtual_address;
    }

    if (actual_boot.id != NodeId{} && actual_boot.id != table.local_id) {
        kademlia_insert(table, actual_boot);
    }

    for (const auto& peer : response.peers) {
        if (peer.id != table.local_id) {
            kademlia_insert(table, peer);
        }
    }
    return true;
}

void handle_find_node(const KademliaTable& table,
                      const FindNodeMessage& request,
                      NeighborsMessage& out_response) {
    out_response.peers =
        kademlia_find_closest(table, request.target, KADEMLIA_K);
}

void handle_neighbors(KademliaTable& table, const NeighborsMessage& message) {
    for (const auto& peer : message.peers) {
        if (peer.id != table.local_id) {
            kademlia_insert(table, peer);
        }
    }
}

bool handle_node_announce(KademliaTable& table,
                          const NodeAnnounceMessage& announce,
                          NodeAnnounceAck& out_ack) {
    out_ack.responder = table.local_id;
    out_ack.accepted = false;

    NodeId derived_id{};
    std::size_t digest_len = derived_id.size();
    if (EVP_Q_digest(nullptr,
                     "SHA256",
                     nullptr,
                     announce.contact.public_key.data(),
                     announce.contact.public_key.size(),
                     derived_id.data(),
                     &digest_len) != 1 ||
        digest_len != derived_id.size() || derived_id != announce.contact.id) {
        return false;
    }

    if (announce.contact.id != table.local_id) {
        kademlia_insert(table, announce.contact);
    }
    out_ack.accepted = true;
    return true;
}

void kademlia_self_lookup(
    KademliaTable& table,
    std::function<std::vector<NodeContact>(const NodeId& peer,
                                           const NodeId& target)> query_fn,
    std::size_t alpha) {
    if (query_fn == nullptr || alpha == 0) {
        return;
    }

    std::unordered_set<NodeId, NodeIdHasher> queried;
    constexpr std::size_t max_rounds = 10;

    for (std::size_t round = 0; round < max_rounds; ++round) {
        auto candidates =
            kademlia_find_closest(table, table.local_id, KADEMLIA_K);
        std::vector<NodeContact> to_query;

        for (const auto& contact : candidates) {
            if (!queried.contains(contact.id)) {
                to_query.push_back(contact);
                if (to_query.size() >= alpha) {
                    break;
                }
            }
        }

        if (to_query.empty()) {
            break;
        }

        for (const auto& peer : to_query) {
            queried.insert(peer.id);
            std::vector<NodeContact> returned_nodes =
                query_fn(peer.id, table.local_id);
            for (const auto& returned_node : returned_nodes) {
                if (returned_node.id != table.local_id) {
                    kademlia_insert(table, returned_node);
                }
            }
        }
    }
}

bool dispatch_join_protocol_message(KademliaTable& table,
                                    const ControlMessage& incoming,
                                    ControlMessage* out_reply,
                                    const NodeContact* local_contact,
                                    bool join_admitted) {
    if (out_reply == nullptr) {
        return false;
    }

    switch (incoming.type) {
        case ControlMessageType::JOIN_REQUEST: {
            if (!join_admitted) {
                return false;
            }
            JoinRequest req{};
            if (!deserialize_join_request(incoming.payload, &req)) {
                return false;
            }
            JoinResponse resp{};
            process_join_request(table, req, resp, local_contact);
            *out_reply =
                control_message_create(ControlMessageType::JOIN_RESPONSE,
                                       incoming.sequence_number,
                                       table.local_id,
                                       serialize_join_response(resp));
            return true;
        }
        case ControlMessageType::FIND_NODE: {
            FindNodeMessage req{};
            if (!deserialize_find_node(incoming.payload, &req)) {
                return false;
            }
            NeighborsMessage resp{};
            handle_find_node(table, req, resp);
            *out_reply = control_message_create(ControlMessageType::NEIGHBORS,
                                                incoming.sequence_number,
                                                table.local_id,
                                                serialize_neighbors(resp));
            return true;
        }
        case ControlMessageType::NODE_ANNOUNCE: {
            NodeAnnounceMessage req{};
            if (!deserialize_node_announce(incoming.payload, &req)) {
                return false;
            }
            NodeAnnounceAck resp{};
            handle_node_announce(table, req, resp);
            *out_reply =
                control_message_create(ControlMessageType::NODE_ANNOUNCE_ACK,
                                       incoming.sequence_number,
                                       table.local_id,
                                       serialize_node_announce_ack(resp));
            return true;
        }
        default:
            return false;
    }
}

} // namespace madoka
