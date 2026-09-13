#include "network/serialization.hpp"

#include <cassert>
#include <iostream>

namespace {

madoka::NodeId make_test_id(char c) {
    madoka::NodeId id{};
    id.fill(static_cast<uint8_t>(c));
    return id;
}

madoka::IPv6 make_test_ip(uint8_t b) {
    madoka::IPv6 ip{};
    ip[0] = 0xfd;
    ip[15] = b;
    return ip;
}

void test_serialization_roundtrip_with_data() {
    std::cout << "[TEST] 1. Testing ControlMessage serialize -> deserialize "
                 "roundtrip...\n";

    const madoka::NodeId node_a = make_test_id('A');
    const std::vector<uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02};

    const madoka::ControlMessage original = madoka::control_message_create(
        madoka::ControlMessageType::NEIGHBOR_ADVERTISEMENT,
        123456789ULL,
        node_a,
        payload);

    const std::vector<uint8_t> encoded =
        madoka::serialize_control_message(original);
    assert(!encoded.empty());
    assert(encoded.size() ==
           madoka::CONTROL_MESSAGE_HEADER_SIZE + payload.size());

    madoka::ControlMessage decoded{};
    std::string err;
    const bool ok =
        madoka::deserialize_control_message(encoded, &decoded, &err);
    assert(ok);
    assert(err.empty());
    assert(decoded == original);

    const madoka::ControlMessage decoded2 =
        madoka::deserialize_control_message(encoded);
    assert(decoded2 == original);

    std::cout << "  -> PASSED: Roundtrip preserves message fields exactly.\n";
}

void test_serialization_empty_payload() {
    std::cout << "[TEST] 2. Testing ControlMessage with empty payload...\n";

    const madoka::NodeId node_b = make_test_id('B');
    const madoka::ControlMessage original = madoka::control_message_create(
        madoka::ControlMessageType::HELLO, 50, node_b, {});

    const std::vector<uint8_t> encoded =
        madoka::serialize_control_message(original);
    assert(encoded.size() == madoka::CONTROL_MESSAGE_HEADER_SIZE);

    const madoka::ControlMessage decoded =
        madoka::deserialize_control_message(encoded);
    assert(decoded.is_valid());
    assert(decoded.type == madoka::ControlMessageType::HELLO);
    assert(decoded.sequence_number == 50);
    assert(decoded.sender == node_b);
    assert(decoded.payload.empty());

    std::cout
        << "  -> PASSED: Empty payload serializes and deserializes cleanly.\n";
}

void test_serialization_invalid_rejected() {
    std::cout
        << "[TEST] 3. Testing rejection of invalid/corrupted payloads...\n";

    const std::vector<uint8_t> too_small(10, 0x01);
    madoka::ControlMessage out{};
    std::string error;
    assert(!madoka::deserialize_control_message(too_small, &out, &error));
    assert(!error.empty());

    const madoka::ControlMessage invalid_small =
        madoka::deserialize_control_message(too_small);
    assert(!invalid_small.is_valid());

    const madoka::NodeId node_a = make_test_id('A');
    madoka::ControlMessage valid = madoka::control_message_create(
        madoka::ControlMessageType::HELLO, 1, node_a, {0xAA});
    std::vector<uint8_t> corrupted = madoka::serialize_control_message(valid);
    corrupted[0] = 99;

    assert(!madoka::deserialize_control_message(corrupted, &out, &error));
    assert(!error.empty());
    assert(!madoka::deserialize_control_message(corrupted).is_valid());

    corrupted = madoka::serialize_control_message(valid);
    corrupted.pop_back();

    assert(!madoka::deserialize_control_message(corrupted, &out, &error));
    assert(!error.empty());

    std::cout << "  -> PASSED: Malformed buffers safely rejected.\n";
}

void test_serialization_payload_helpers() {
    std::cout << "[TEST] 4. Testing payload helper serializations...\n";

    const madoka::NodeId node_a = make_test_id('A');
    const madoka::NodeId node_b = make_test_id('B');
    const madoka::IPv6 ip_a = make_test_ip(0x0a);

    const madoka::HelloMessage hello =
        madoka::heartbeat_create_hello(node_a, 5000);
    const std::vector<uint8_t> hello_bytes =
        madoka::serialize_hello_message(hello);
    const madoka::HelloMessage hello_decoded =
        madoka::deserialize_hello_message(hello_bytes);
    assert(hello_decoded == hello);

    const madoka::NeighborAdvertisement adv{
        .node_id = node_a,
        .address = ip_a,
        .timestamp = 3000,
        .sequence_number = 77,
    };
    const std::vector<uint8_t> adv_bytes =
        madoka::serialize_neighbor_advertisement(adv);
    const madoka::NeighborAdvertisement adv_decoded =
        madoka::deserialize_neighbor_advertisement(adv_bytes);
    assert(adv_decoded == adv);

    madoka::RouteTable table = madoka::routing_init();
    madoka::routing_add_route(
        table, madoka::route_create(ip_a, node_b, 2, 4000, node_b));
    madoka::RouteAdvertisement r_adv =
        madoka::route_create_advertisement(node_a, table, 99);
    r_adv.generation = 7;

    const std::vector<uint8_t> radv_bytes =
        madoka::serialize_route_advertisement(r_adv);
    const madoka::RouteAdvertisement radv_decoded =
        madoka::deserialize_route_advertisement(radv_bytes);
    assert(radv_decoded.sender == r_adv.sender);
    assert(radv_decoded.generation == r_adv.generation);
    assert(radv_decoded.sequence_number == r_adv.sequence_number);
    assert(radv_decoded.routes.size() == 1);
    assert(radv_decoded.routes[0].destination_node == node_b);
    assert(radv_decoded.routes[0].destination == ip_a);
    assert(radv_decoded.routes[0].metric == 2);
    assert(radv_decoded.routes[0].next_hop == madoka::NodeId{});
    assert(radv_decoded.routes[0].last_update == 0);

    std::cout << "  -> PASSED: All payload helpers roundtrip successfully.\n";
}

void test_serialization_kademlia_messages() {
    std::cout
        << "[TEST] 5. Testing Kademlia distributed messages serialization...\n";

    const madoka::NodeId node_a = make_test_id('A');
    const madoka::NodeId node_b = make_test_id('B');
    const madoka::IPv6 ip_a = make_test_ip(0x0a);

    std::array<uint8_t, 32> pub_a{};
    pub_a.fill(0xAA);

    madoka::NodeContact contact_a{
        .id = node_a,
        .public_key = pub_a,
        .virtual_address = ip_a,
        .endpoint = "192.168.1.10:9000",
        .last_seen_ms = 12345678,
        .rtt_ms = 42,
        .failed_pings = 1,
    };
    std::vector<uint8_t> contact_bytes =
        madoka::serialize_node_contact(contact_a);
    madoka::NodeContact contact_decoded =
        madoka::deserialize_node_contact(contact_bytes);
    assert(contact_decoded == contact_a);

    madoka::JoinRequest req{
        .node_id = node_a,
        .public_key = pub_a,
        .virtual_address = ip_a,
        .endpoint = "[::1]:9000",
        .timestamp = 987654321ULL,
        .nonce = 55555ULL,
        .invite_token = "madoka://invite/example",
    };
    std::vector<uint8_t> req_bytes = madoka::serialize_join_request(req);
    madoka::JoinRequest req_decoded =
        madoka::deserialize_join_request(req_bytes);
    assert(req_decoded == req);

    madoka::NodeContact bootstrap_contact{
        .id = node_b,
        .endpoint = "[::1]:9001",
        .last_seen_ms = 99,
        .rtt_ms = 7,
    };
    madoka::JoinResponse resp{
        .accepted = true,
        .bootstrap_contact = bootstrap_contact,
        .bootstrap_id = node_b,
        .peers = {contact_a},
    };
    std::vector<uint8_t> resp_bytes = madoka::serialize_join_response(resp);
    madoka::JoinResponse resp_decoded =
        madoka::deserialize_join_response(resp_bytes);
    assert(resp_decoded == resp);
    assert(resp_decoded.bootstrap_contact.endpoint == "[::1]:9001");

    madoka::FindNodeMessage find_node{.target = node_a};
    std::vector<uint8_t> find_bytes = madoka::serialize_find_node(find_node);
    madoka::FindNodeMessage find_decoded =
        madoka::deserialize_find_node(find_bytes);
    assert(find_decoded == find_node);

    madoka::NeighborsMessage neighbors{.peers = {contact_a}};
    std::vector<uint8_t> neighbors_bytes =
        madoka::serialize_neighbors(neighbors);
    madoka::NeighborsMessage neighbors_decoded =
        madoka::deserialize_neighbors(neighbors_bytes);
    assert(neighbors_decoded == neighbors);

    madoka::NodeAnnounceMessage announce{.contact = contact_a, .nonce = 777};
    std::vector<uint8_t> announce_bytes =
        madoka::serialize_node_announce(announce);
    madoka::NodeAnnounceMessage announce_decoded =
        madoka::deserialize_node_announce(announce_bytes);
    assert(announce_decoded == announce);

    madoka::NodeAnnounceAck ack{.accepted = true, .responder = node_b};
    std::vector<uint8_t> ack_bytes = madoka::serialize_node_announce_ack(ack);
    madoka::NodeAnnounceAck ack_decoded =
        madoka::deserialize_node_announce_ack(ack_bytes);
    assert(ack_decoded == ack);

    madoka::ControlMessage ctrl_msg = madoka::control_message_create(
        madoka::ControlMessageType::JOIN_REQUEST, 100, node_a, req_bytes);
    std::vector<uint8_t> ctrl_bytes =
        madoka::serialize_control_message(ctrl_msg);
    madoka::ControlMessage ctrl_decoded =
        madoka::deserialize_control_message(ctrl_bytes);
    assert(ctrl_decoded.is_valid());
    assert(ctrl_decoded.type == madoka::ControlMessageType::JOIN_REQUEST);
    assert(ctrl_decoded.payload == req_bytes);

    std::cout << "  -> PASSED: All Kademlia distributed messages serialized "
                 "cleanly.\n";
}

} // namespace

int main() {
    std::cout << "=== Madoka Mesh Serialization Unit Tests ===\n";

    test_serialization_roundtrip_with_data();
    test_serialization_empty_payload();
    test_serialization_invalid_rejected();
    test_serialization_payload_helpers();
    test_serialization_kademlia_messages();

    std::cout << "=== All Serialization Unit Tests Passed Successfully ===\n";
    return 0;
}
