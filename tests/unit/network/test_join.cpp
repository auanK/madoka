#include "crypto/identity.hpp"
#include "network/control_message.hpp"
#include "network/join.hpp"
#include "network/node_state.hpp"
#include "network/serialization.hpp"
#include "protocol/codec.hpp"
#include "protocol/message.hpp"
#include "transport/session.hpp"

#include <atomic>
#include <cassert>
#include <iostream>
#include <openssl/evp.h>
#include <thread>

using namespace madoka;

std::array<uint8_t, 32> extract_public_key(const Identity& id) {
    std::array<uint8_t, 32> pub{};
    std::size_t len = pub.size();
    auto* pkey = static_cast<EVP_PKEY*>(id.key);
    assert(pkey != nullptr);
    assert(EVP_PKEY_get_raw_public_key(pkey, pub.data(), &len) == 1);
    return pub;
}

void test_join_identity_validation() {
    Identity alice{};
    std::string err;
    assert(identity_generate(&alice, &err));

    const auto alice_pub = extract_public_key(alice);

    KademliaTable bootstrap_table{};
    NodeId boot_id{99};
    kademlia_init(&bootstrap_table, boot_id);

    JoinRequest req{
        .node_id = alice.id,
        .public_key = alice_pub,
        .virtual_address = IPv6{0xfd, 0x00, 0x01},
        .endpoint = "10.0.0.2:9000",
        .timestamp = 1000,
        .nonce = 12345,
    };

    JoinResponse resp{};
    assert(process_join_request(bootstrap_table, req, resp));
    assert(resp.accepted);
    assert(resp.bootstrap_id == boot_id);
    assert(kademlia_find(bootstrap_table, alice.id) != nullptr);

    JoinRequest forged_req = req;
    forged_req.public_key[0] ^= 0xFF;
    JoinResponse forged_resp{};
    assert(!process_join_request(bootstrap_table, forged_req, forged_resp));
    assert(!forged_resp.accepted);

    identity_close(&alice);
}

void test_bootstrap_contact_uses_local_endpoint() {
    Identity bootstrap{};
    Identity joining{};
    std::string err;
    assert(identity_generate(&bootstrap, &err));
    assert(identity_generate(&joining, &err));

    KademliaTable table{};
    kademlia_init(&table, bootstrap.id);
    const NodeContact local_contact{
        .id = bootstrap.id,
        .public_key = extract_public_key(bootstrap),
        .virtual_address = IPv6{0xfd, 0x00, 0x01},
        .endpoint = "[::1]:9000",
        .last_seen_ms = 100,
        .rtt_ms = 3,
        .failed_pings = 0,
    };
    const JoinRequest request{
        .node_id = joining.id,
        .public_key = extract_public_key(joining),
        .virtual_address = IPv6{0xfd, 0x00, 0x02},
        .endpoint = "[::1]:9001",
        .timestamp = 200,
        .nonce = 1,
    };

    JoinResponse response{};
    assert(process_join_request(table, request, response, &local_contact));
    assert(response.bootstrap_contact == local_contact);
    assert(response.bootstrap_contact.endpoint == "[::1]:9000");

    identity_close(&joining);
    identity_close(&bootstrap);
}

void test_malformed_join_payload_only_rejects_dispatch() {
    KademliaTable table{};
    kademlia_init(&table, NodeId{1});

    const ControlMessage malformed = control_message_create(
        ControlMessageType::JOIN_REQUEST, 1, NodeId{2}, {0x01, 0x02});
    ControlMessage reply{};
    assert(!dispatch_join_protocol_message(table, malformed, &reply));
    assert(!reply.is_valid());
    assert(kademlia_total_contacts(table) == 0);
}

void test_join_request_processing() {
    KademliaTable boot_table{};
    NodeId boot_id{10};
    kademlia_init(&boot_table, boot_id);

    Identity c_id{};
    std::string err;
    assert(identity_generate(&c_id, &err));
    NodeContact contact_c{
        .id = c_id.id,
        .public_key = extract_public_key(c_id),
        .virtual_address = IPv6{0xfd, 0x00, 0x03},
        .endpoint = "10.0.0.3:9000",
        .last_seen_ms = 500,
    };
    assert(kademlia_insert(boot_table, contact_c));

    Identity a_id{};
    assert(identity_generate(&a_id, &err));
    JoinRequest a_req{
        .node_id = a_id.id,
        .public_key = extract_public_key(a_id),
        .virtual_address = IPv6{0xfd, 0x00, 0x01},
        .endpoint = "10.0.0.1:9000",
        .timestamp = 1000,
        .nonce = 1,
    };

    JoinResponse resp{};
    assert(process_join_request(boot_table, a_req, resp));
    assert(resp.accepted);
    assert(resp.bootstrap_id == boot_id);
    assert(resp.peers.size() == 2);

    assert(kademlia_find(boot_table, a_id.id) != nullptr);
    assert(kademlia_find(boot_table, c_id.id) != nullptr);

    identity_close(&a_id);
    identity_close(&c_id);
}

void test_node_state_transitions() {
    NodeState state = NodeState::CREATED;
    std::string err;

    assert(!node_state_transition(state, NodeState::ACTIVE, &err));
    assert(!err.empty());
    assert(state == NodeState::CREATED);

    assert(node_state_transition(state, NodeState::DISCOVERING, &err));
    assert(state == NodeState::DISCOVERING);

    assert(node_state_transition(state, NodeState::JOINING_NETWORK, &err));
    assert(state == NodeState::JOINING_NETWORK);

    assert(node_state_transition(state, NodeState::ACTIVE, &err));
    assert(state == NodeState::ACTIVE);

    assert(node_state_transition(state, NodeState::LEAVING, &err));
    assert(state == NodeState::LEAVING);

    assert(node_state_transition(state, NodeState::CREATED, &err));
    assert(state == NodeState::CREATED);
}

void test_kademlia_self_lookup() {
    KademliaTable a_table{};
    NodeId a_id{1};
    kademlia_init(&a_table, a_id);

    NodeId b_id{2};
    NodeId c_id{3};

    NodeContact b_contact{.id = b_id, .endpoint = "10.0.0.2:9000"};
    assert(kademlia_insert(a_table, b_contact));
    assert(kademlia_total_contacts(a_table) == 1);

    auto mock_query = [&](const NodeId& peer,
                          const NodeId&) -> std::vector<NodeContact> {
        if (peer == b_id) {
            return {NodeContact{.id = c_id, .endpoint = "10.0.0.3:9000"}};
        }
        return {};
    };

    kademlia_self_lookup(a_table, mock_query, 3);

    assert(kademlia_total_contacts(a_table) == 2);
    assert(kademlia_find(a_table, b_id) != nullptr);
    assert(kademlia_find(a_table, c_id) != nullptr);
}

void test_full_3_node_join_simulation() {
    Identity a_ident{};
    Identity b_ident{};
    Identity c_ident{};
    std::string err;
    assert(identity_generate(&a_ident, &err));
    assert(identity_generate(&b_ident, &err));
    assert(identity_generate(&c_ident, &err));

    const auto a_pub = extract_public_key(a_ident);
    const auto b_pub = extract_public_key(b_ident);
    const auto c_pub = extract_public_key(c_ident);

    KademliaTable b_table{};
    kademlia_init(&b_table, b_ident.id);
    NodeContact c_contact{
        .id = c_ident.id,
        .public_key = c_pub,
        .virtual_address = IPv6{0xfd, 0x00, 0x03},
        .endpoint = "192.168.1.3:9000",
        .last_seen_ms = 100,
    };
    assert(kademlia_insert(b_table, c_contact));

    NodeState a_state = NodeState::CREATED;
    KademliaTable a_table{};
    kademlia_init(&a_table, a_ident.id);

    assert(node_state_transition(a_state, NodeState::DISCOVERING, &err));

    JoinRequest join_req{
        .node_id = a_ident.id,
        .public_key = a_pub,
        .virtual_address = IPv6{0xfd, 0x00, 0x01},
        .endpoint = "192.168.1.1:9000",
        .timestamp = 1000,
        .nonce = 42,
    };

    JoinResponse join_resp{};
    assert(process_join_request(b_table, join_req, join_resp));
    assert(join_resp.accepted);
    assert(join_resp.bootstrap_id == b_ident.id);

    assert(node_state_transition(a_state, NodeState::JOINING_NETWORK, &err));

    NodeContact b_contact{
        .id = b_ident.id,
        .public_key = b_pub,
        .virtual_address = IPv6{0xfd, 0x00, 0x02},
        .endpoint = "192.168.1.2:9000",
        .last_seen_ms = 1000,
    };
    assert(kademlia_insert(a_table, b_contact));

    auto query_fn = [&](const NodeId& peer,
                        const NodeId& target) -> std::vector<NodeContact> {
        if (peer == b_ident.id) {
            return kademlia_find_closest(b_table, target, 20);
        }
        return {};
    };

    kademlia_self_lookup(a_table, query_fn, 3);

    assert(node_state_transition(a_state, NodeState::ACTIVE, &err));

    assert(a_state == NodeState::ACTIVE);

    assert(kademlia_find(b_table, a_ident.id) != nullptr);
    assert(kademlia_find(b_table, c_ident.id) != nullptr);

    assert(kademlia_find(a_table, b_ident.id) != nullptr);
    assert(kademlia_find(a_table, c_ident.id) != nullptr);

    identity_close(&a_ident);
    identity_close(&b_ident);
    identity_close(&c_ident);
}

void test_handlers_find_node_and_neighbors() {
    KademliaTable a_table{};
    NodeId a_id{1};
    kademlia_init(&a_table, a_id);

    NodeId b_id{2};
    NodeContact b_contact{
        .id = b_id,
        .virtual_address = IPv6{0xfd, 0x00, 0x02},
        .endpoint = "[::1]:9002",
        .last_seen_ms = 100,
    };
    assert(kademlia_insert(a_table, b_contact));

    FindNodeMessage fn_req{.target = b_id};
    NeighborsMessage fn_resp{};
    handle_find_node(a_table, fn_req, fn_resp);
    assert(!fn_resp.peers.empty());
    assert(fn_resp.peers[0].id == b_id);

    KademliaTable c_table{};
    NodeId c_id{3};
    kademlia_init(&c_table, c_id);
    handle_neighbors(c_table, fn_resp);
    assert(kademlia_total_contacts(c_table) == 1);
    assert(kademlia_find(c_table, b_id) != nullptr);
}

void test_handle_node_announce() {
    Identity alice{};
    std::string err;
    assert(identity_generate(&alice, &err));
    const auto alice_pub = extract_public_key(alice);

    KademliaTable table{};
    NodeId bob_id{20};
    kademlia_init(&table, bob_id);

    NodeAnnounceMessage valid_ann{
        .contact =
            NodeContact{
                .id = alice.id,
                .public_key = alice_pub,
                .virtual_address = IPv6{0xfd, 0x00, 0x01},
                .endpoint = "[::1]:9001",
                .last_seen_ms = 500,
            },
        .nonce = 1234,
    };
    NodeAnnounceAck ack{};
    assert(handle_node_announce(table, valid_ann, ack));
    assert(ack.accepted);
    assert(ack.responder == bob_id);
    assert(kademlia_find(table, alice.id) != nullptr);

    NodeAnnounceMessage forged_ann = valid_ann;
    forged_ann.contact.public_key[0] ^= 0xFF;
    NodeAnnounceAck forged_ack{};
    assert(!handle_node_announce(table, forged_ann, forged_ack));
    assert(!forged_ack.accepted);

    identity_close(&alice);
}

void test_dispatch_join_protocol_message() {
    Identity alice{};
    std::string err;
    assert(identity_generate(&alice, &err));
    const auto alice_pub = extract_public_key(alice);

    KademliaTable table{};
    NodeId boot_id{99};
    kademlia_init(&table, boot_id);

    JoinRequest req{
        .node_id = alice.id,
        .public_key = alice_pub,
        .virtual_address = IPv6{0xfd, 0x00, 0x01},
        .endpoint = "[::1]:9001",
        .timestamp = 1000,
        .nonce = 1,
    };
    ControlMessage in_ctrl =
        control_message_create(ControlMessageType::JOIN_REQUEST,
                               10,
                               alice.id,
                               serialize_join_request(req));
    ControlMessage out_ctrl{};
    assert(dispatch_join_protocol_message(
        table, in_ctrl, &out_ctrl, nullptr, true));
    assert(out_ctrl.type == ControlMessageType::JOIN_RESPONSE);
    assert(out_ctrl.sequence_number == 10);
    JoinResponse resp = deserialize_join_response(out_ctrl.payload);
    assert(resp.accepted);
    assert(resp.bootstrap_id == boot_id);

    FindNodeMessage fn_req{.target = alice.id};
    ControlMessage fn_ctrl =
        control_message_create(ControlMessageType::FIND_NODE,
                               11,
                               alice.id,
                               serialize_find_node(fn_req));
    ControlMessage fn_out{};
    assert(dispatch_join_protocol_message(table, fn_ctrl, &fn_out));
    assert(fn_out.type == ControlMessageType::NEIGHBORS);
    assert(fn_out.sequence_number == 11);

    NodeAnnounceMessage ann_req{
        .contact =
            NodeContact{
                .id = alice.id,
                .public_key = alice_pub,
                .virtual_address = IPv6{0xfd, 0x00, 0x01},
                .endpoint = "[::1]:9001",
                .last_seen_ms = 1000,
            },
        .nonce = 42,
    };
    ControlMessage ann_ctrl =
        control_message_create(ControlMessageType::NODE_ANNOUNCE,
                               12,
                               alice.id,
                               serialize_node_announce(ann_req));
    ControlMessage ann_out{};
    assert(dispatch_join_protocol_message(table, ann_ctrl, &ann_out));
    assert(ann_out.type == ControlMessageType::NODE_ANNOUNCE_ACK);
    assert(ann_out.sequence_number == 12);
    NodeAnnounceAck ack = deserialize_node_announce_ack(ann_out.payload);
    assert(ack.accepted);
    assert(ack.responder == boot_id);

    identity_close(&alice);
}

void test_real_tcp_distributed_join_integration() {
    std::cout
        << "[TEST] Running real TCP distributed join integration test...\n";

    Identity a_ident{};
    std::string err;
    assert(identity_generate(&a_ident, &err));
    const auto a_pub = extract_public_key(a_ident);

    KademliaTable a_table{};
    kademlia_init(&a_table, a_ident.id);

    Identity c_ident{};
    assert(identity_generate(&c_ident, &err));
    const auto c_pub = extract_public_key(c_ident);
    NodeContact c_contact{
        .id = c_ident.id,
        .public_key = c_pub,
        .virtual_address = IPv6{0xfd, 0x00, 0x03},
        .endpoint = "[::1]:9003",
        .last_seen_ms = 500,
    };
    assert(kademlia_insert(a_table, c_contact));

    TransportServerState a_server{};
    assert(transport_server_init(&a_server, 0, "::1"));
    assert(transport_server_start(&a_server));
    const uint16_t a_port = transport_server_local_port(a_server);
    assert(a_port > 0);

    std::thread server_thread([&]() {
        TransportSessionState server_session{};
        assert(transport_accept(
            &a_server, &server_session, std::chrono::milliseconds{3000}));
        assert(transport_is_open(server_session));

        for (int i = 0; i < 3; ++i) {
            Message in_msg{};
            bool closed = false;
            if (!transport_receive(&server_session,
                                   &in_msg,
                                   std::chrono::milliseconds{3000},
                                   &closed,
                                   &err)) {
                break;
            }
            assert(in_msg.type == MessageType::Control);
            ControlMessage ctrl_in =
                deserialize_control_message(in_msg.payload);
            assert(ctrl_in.is_valid());

            ControlMessage ctrl_out{};
            assert(dispatch_join_protocol_message(
                a_table, ctrl_in, &ctrl_out, nullptr, true));

            Message out_wire{.type = MessageType::Control,
                             .payload = serialize_control_message(ctrl_out)};
            assert(transport_send(&server_session, out_wire));
        }

        transport_close(&server_session);
        transport_server_close(&a_server);
    });

    Identity b_ident{};
    assert(identity_generate(&b_ident, &err));
    const auto b_pub = extract_public_key(b_ident);

    NodeState b_state = NodeState::CREATED;
    KademliaTable b_table{};
    kademlia_init(&b_table, b_ident.id);

    assert(node_state_transition(b_state, NodeState::DISCOVERING, &err));

    assert(node_state_transition(b_state, NodeState::JOINING_NETWORK, &err));

    TransportSessionState b_session{};
    assert(transport_connect(
        &b_session, "::1", a_port, std::chrono::milliseconds{3000}, &err));
    assert(transport_is_open(b_session));

    JoinRequest b_join_req{
        .node_id = b_ident.id,
        .public_key = b_pub,
        .virtual_address = IPv6{0xfd, 0x00, 0x02},
        .endpoint = "[::1]:9002",
        .timestamp = 1000,
        .nonce = 1,
    };
    ControlMessage join_ctrl =
        control_message_create(ControlMessageType::JOIN_REQUEST,
                               1,
                               b_ident.id,
                               serialize_join_request(b_join_req));
    Message join_msg{.type = MessageType::Control,
                     .payload = serialize_control_message(join_ctrl)};
    assert(transport_send(&b_session, join_msg, &err));

    Message join_reply_wire{};
    assert(transport_receive(&b_session,
                             &join_reply_wire,
                             std::chrono::milliseconds{3000},
                             nullptr,
                             &err));
    assert(join_reply_wire.type == MessageType::Control);
    ControlMessage join_reply_ctrl =
        deserialize_control_message(join_reply_wire.payload);
    assert(join_reply_ctrl.type == ControlMessageType::JOIN_RESPONSE);

    JoinResponse b_join_resp =
        deserialize_join_response(join_reply_ctrl.payload);
    assert(b_join_resp.accepted);
    assert(b_join_resp.bootstrap_id == a_ident.id);

    NodeContact a_contact{
        .id = a_ident.id,
        .public_key = a_pub,
        .virtual_address = IPv6{0xfd, 0x00, 0x01},
        .endpoint = "[::1]:" + std::to_string(a_port),
        .last_seen_ms = 1000,
    };
    assert(handle_join_response(b_table, b_join_resp, a_contact));

    FindNodeMessage fn_req{.target = b_ident.id};
    ControlMessage fn_ctrl =
        control_message_create(ControlMessageType::FIND_NODE,
                               2,
                               b_ident.id,
                               serialize_find_node(fn_req));
    Message fn_wire{.type = MessageType::Control,
                    .payload = serialize_control_message(fn_ctrl)};
    assert(transport_send(&b_session, fn_wire, &err));

    Message fn_reply_wire{};
    assert(transport_receive(&b_session,
                             &fn_reply_wire,
                             std::chrono::milliseconds{3000},
                             nullptr,
                             &err));
    ControlMessage fn_reply_ctrl =
        deserialize_control_message(fn_reply_wire.payload);
    assert(fn_reply_ctrl.type == ControlMessageType::NEIGHBORS);

    NeighborsMessage neighbors = deserialize_neighbors(fn_reply_ctrl.payload);
    handle_neighbors(b_table, neighbors);

    NodeAnnounceMessage ann{
        .contact =
            NodeContact{
                .id = b_ident.id,
                .public_key = b_pub,
                .virtual_address = IPv6{0xfd, 0x00, 0x02},
                .endpoint = "[::1]:9002",
                .last_seen_ms = 1000,
            },
        .nonce = 99,
    };
    ControlMessage ann_ctrl =
        control_message_create(ControlMessageType::NODE_ANNOUNCE,
                               3,
                               b_ident.id,
                               serialize_node_announce(ann));
    Message ann_wire{.type = MessageType::Control,
                     .payload = serialize_control_message(ann_ctrl)};
    assert(transport_send(&b_session, ann_wire, &err));

    Message ann_ack_wire{};
    assert(transport_receive(&b_session,
                             &ann_ack_wire,
                             std::chrono::milliseconds{3000},
                             nullptr,
                             &err));
    ControlMessage ann_ack_ctrl =
        deserialize_control_message(ann_ack_wire.payload);
    assert(ann_ack_ctrl.type == ControlMessageType::NODE_ANNOUNCE_ACK);
    NodeAnnounceAck ack = deserialize_node_announce_ack(ann_ack_ctrl.payload);
    assert(ack.accepted);
    assert(ack.responder == a_ident.id);

    assert(node_state_transition(b_state, NodeState::ACTIVE, &err));
    assert(b_state == NodeState::ACTIVE);

    transport_close(&b_session);
    server_thread.join();

    assert(kademlia_find(a_table, b_ident.id) != nullptr);

    assert(kademlia_find(b_table, a_ident.id) != nullptr);

    assert(kademlia_find(b_table, c_ident.id) != nullptr);

    assert(kademlia_total_contacts(a_table) >= 2);
    assert(kademlia_total_contacts(b_table) >= 2);

    identity_close(&a_ident);
    identity_close(&b_ident);
    identity_close(&c_ident);

    std::cout << "  -> PASSED: Real TCP distributed join integration test "
                 "completed successfully.\n";
}

void test_multiple_sessions_are_independent() {
    Identity bootstrap{};
    Identity first{};
    Identity second{};
    std::string err;
    assert(identity_generate(&bootstrap, &err));
    assert(identity_generate(&first, &err));
    assert(identity_generate(&second, &err));

    KademliaTable table{};
    kademlia_init(&table, bootstrap.id);

    TransportServerState server{};
    assert(transport_server_init(&server, 0, "::1"));
    assert(transport_server_start(&server));
    const uint16_t port = transport_server_local_port(server);

    std::atomic<int> ready{0};
    std::atomic<bool> release{false};
    auto client = [&](Identity& identity, std::string endpoint, bool survives) {
        std::string client_err;
        TransportSessionState session{};
        assert(transport_connect(&session, "::1", port));
        JoinRequest request{
            .node_id = identity.id,
            .public_key = extract_public_key(identity),
            .endpoint = std::move(endpoint),
        };
        const auto control =
            control_message_create(ControlMessageType::JOIN_REQUEST,
                                   1,
                                   identity.id,
                                   serialize_join_request(request));
        assert(transport_send(
            &session,
            Message{.type = MessageType::Control,
                    .payload = serialize_control_message(control)}));

        Message response_wire{};
        assert(transport_receive(
            &session, &response_wire, std::chrono::milliseconds{2000}));
        ControlMessage response_control{};
        assert(deserialize_control_message(
            response_wire.payload, &response_control, &client_err));
        JoinResponse response{};
        assert(deserialize_join_response(
            response_control.payload, &response, &client_err));
        assert(response.accepted);
        ready.fetch_add(1);

        while (!release.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
        if (survives) {
            FindNodeMessage find{.target = identity.id};
            const auto find_control =
                control_message_create(ControlMessageType::FIND_NODE,
                                       2,
                                       identity.id,
                                       serialize_find_node(find));
            assert(transport_send(
                &session,
                Message{.type = MessageType::Control,
                        .payload = serialize_control_message(find_control)}));
            Message find_response{};
            assert(transport_receive(
                &session, &find_response, std::chrono::milliseconds{2000}));
            assert(find_response.type == MessageType::Control);
        }
        transport_close(&session);
    };

    std::thread first_client(client, std::ref(first), "[::1]:9001", false);
    std::thread second_client(client, std::ref(second), "[::1]:9002", true);

    TransportSessionState first_server_session{};
    TransportSessionState second_server_session{};
    auto accept_join = [&](TransportSessionState& session) {
        assert(transport_accept(
            &server, &session, std::chrono::milliseconds{2000}));
        Message wire{};
        assert(transport_receive(
            &session, &wire, std::chrono::milliseconds{2000}));
        ControlMessage incoming{};
        assert(deserialize_control_message(wire.payload, &incoming, &err));
        JoinRequest request{};
        assert(deserialize_join_request(incoming.payload, &request, &err));
        JoinResponse response{};
        assert(process_join_request(table, request, response));
        const auto reply =
            control_message_create(ControlMessageType::JOIN_RESPONSE,
                                   incoming.sequence_number,
                                   bootstrap.id,
                                   serialize_join_response(response));
        assert(transport_send(
            &session,
            Message{.type = MessageType::Control,
                    .payload = serialize_control_message(reply)}));
        return request.node_id;
    };

    const NodeId first_id = accept_join(first_server_session);
    const NodeId second_id = accept_join(second_server_session);
    assert((first_id == first.id || first_id == second.id) &&
           (second_id == first.id || second_id == second.id) &&
           first_id != second_id);
    while (ready.load() != 2) {
        std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }

    TransportSessionState* close_session =
        first_id == first.id ? &first_server_session : &second_server_session;
    TransportSessionState* keep_session =
        first_id == first.id ? &second_server_session : &first_server_session;
    transport_close(close_session);
    release.store(true);

    Message find_wire{};
    assert(transport_receive(
        keep_session, &find_wire, std::chrono::milliseconds{2000}));
    ControlMessage find_incoming{};
    assert(
        deserialize_control_message(find_wire.payload, &find_incoming, &err));
    ControlMessage find_reply{};
    assert(dispatch_join_protocol_message(table, find_incoming, &find_reply));
    assert(transport_send(
        keep_session,
        Message{.type = MessageType::Control,
                .payload = serialize_control_message(find_reply)}));

    first_client.join();
    second_client.join();
    transport_close(keep_session);
    transport_server_close(&server);
    identity_close(&second);
    identity_close(&first);
    identity_close(&bootstrap);
}

int main() {
    test_join_identity_validation();
    test_bootstrap_contact_uses_local_endpoint();
    test_malformed_join_payload_only_rejects_dispatch();
    test_join_request_processing();
    test_node_state_transitions();
    test_kademlia_self_lookup();
    test_full_3_node_join_simulation();
    test_handlers_find_node_and_neighbors();
    test_handle_node_announce();
    test_dispatch_join_protocol_message();
    test_real_tcp_distributed_join_integration();
    test_multiple_sessions_are_independent();

    std::cout << "All Join protocol unit tests passed successfully.\n";
    return 0;
}
