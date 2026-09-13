#include "network/control_message.hpp"

#include <cassert>
#include <iostream>

namespace {

madoka::NodeId make_test_id(char c) {
    madoka::NodeId id{};
    id.fill(static_cast<uint8_t>(c));
    return id;
}

void test_control_message_hello_creation() {
    std::cout << "[TEST] 1. Testing HELLO control message creation...\n";

    const madoka::NodeId node_a = make_test_id('A');
    const std::vector<uint8_t> dummy_payload = {0x01, 0x02, 0x03, 0x04};

    const madoka::ControlMessage msg = madoka::control_message_create(
        madoka::ControlMessageType::HELLO, 42, node_a, dummy_payload);

    assert(msg.is_valid());
    assert(msg.type == madoka::ControlMessageType::HELLO);
    assert(msg.sequence_number == 42);
    assert(msg.sender == node_a);
    assert(msg.payload == dummy_payload);

    std::cout << "  -> PASSED: HELLO control message properly created.\n";
}

void test_control_message_type_identification() {
    std::cout << "[TEST] 2. Testing ControlMessageType string conversions...\n";

    assert(madoka::to_string(madoka::ControlMessageType::HELLO) == "HELLO");
    assert(
        madoka::to_string(madoka::ControlMessageType::NEIGHBOR_ADVERTISEMENT) ==
        "NEIGHBOR_ADVERTISEMENT");
    assert(madoka::to_string(madoka::ControlMessageType::ROUTE_ADVERTISEMENT) ==
           "ROUTE_ADVERTISEMENT");
    assert(madoka::to_string(madoka::ControlMessageType::Invalid) == "Invalid");

    std::cout << "  -> PASSED: ControlMessageType identification correct.\n";
}

void test_control_message_sequence_preservation() {
    std::cout << "[TEST] 3. Testing sequence number preservation...\n";

    const madoka::NodeId node_b = make_test_id('B');
    for (uint64_t seq : {0ULL, 1ULL, 100ULL, 9999999999ULL}) {
        const madoka::ControlMessage msg = madoka::control_message_create(
            madoka::ControlMessageType::ROUTE_ADVERTISEMENT, seq, node_b);
        assert(msg.sequence_number == seq);
    }

    std::cout << "  -> PASSED: Sequence numbers preserved across values.\n";
}

void test_control_message_send_and_handle() {
    std::cout << "[TEST] 4. Testing send_control_message & "
                 "handle_control_message...\n";

    const madoka::NodeId node_a = make_test_id('A');
    const madoka::NodeId node_b = make_test_id('B');
    madoka::IPv6 dummy_ip{};
    dummy_ip[0] = 0xfd;

    madoka::Peer peer_b = madoka::peer_create(
        node_b, dummy_ip, "127.0.0.1:4242", madoka::PeerState::Disconnected);

    bool send_called = false;
    madoka::set_control_message_sender(
        [&](madoka::Peer& p, const madoka::ControlMessage& m) {
            send_called = true;
            assert(p.id == node_b);
            assert(m.sequence_number == 10);
        });

    const madoka::ControlMessage msg = madoka::control_message_create(
        madoka::ControlMessageType::HELLO, 10, node_a);

    madoka::send_control_message(peer_b, msg);
    assert(!send_called);

    peer_b.state = madoka::PeerState::Connected;
    madoka::send_control_message(peer_b, msg);
    assert(send_called);

    bool handle_called = false;
    madoka::set_control_message_handler(
        [&](const madoka::ControlMessage& received) {
            handle_called = true;
            assert(received.sender == node_a);
            assert(received.sequence_number == 10);
        });

    madoka::handle_control_message(msg);
    assert(handle_called);

    madoka::set_control_message_sender(nullptr);
    madoka::set_control_message_handler(nullptr);

    std::cout << "  -> PASSED: send/handle control message hooks verified.\n";
}

} // namespace

int main() {
    std::cout << "=== Madoka Mesh Control Message Unit Tests ===\n";

    test_control_message_hello_creation();
    test_control_message_type_identification();
    test_control_message_sequence_preservation();
    test_control_message_send_and_handle();

    std::cout << "=== All Control Message Unit Tests Passed Successfully ===\n";
    return 0;
}
