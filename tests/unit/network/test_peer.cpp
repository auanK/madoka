#include "network/peer.hpp"

#include <cassert>
#include <iostream>

void test_peer_create() {
    std::cout << "[TEST] 1. Creating valid Peer structure...\n";

    madoka::NodeId id{};
    id.fill(0xAA);
    madoka::IPv6 vaddr{};
    vaddr.fill(0xFD);

    madoka::Peer peer = madoka::peer_create(
        id, vaddr, "192.168.1.100:4242", madoka::PeerState::Unknown, 1000);

    assert(peer.id == id);
    assert(peer.virtual_address == vaddr);
    assert(peer.endpoint == "192.168.1.100:4242");
    assert(peer.state == madoka::PeerState::Unknown);
    assert(peer.last_seen == 1000);

    std::cout << "  -> PASSED: Valid peer instantiated with correct fields.\n";
}

void test_peer_equality() {
    std::cout << "[TEST] 2. Testing peer equality by Node ID...\n";

    madoka::NodeId id1{};
    id1.fill(0x01);
    madoka::NodeId id2{};
    id2.fill(0x02);

    madoka::IPv6 vaddr{};

    madoka::Peer peer1 = madoka::peer_create(id1, vaddr, "10.0.0.1:5000");
    madoka::Peer peer1_alias = madoka::peer_create(
        id1, vaddr, "10.0.0.2:6000", madoka::PeerState::Connected);
    madoka::Peer peer2 = madoka::peer_create(id2, vaddr);

    assert(madoka::peer_equal(peer1, peer1_alias));
    assert(!madoka::peer_equal(peer1, peer2));

    std::cout << "  -> PASSED: Peer equality properly derives from Node ID.\n";
}

void test_peer_state_update() {
    std::cout
        << "[TEST] 3. Testing state transitions and timestamp update...\n";

    madoka::NodeId id{};
    madoka::IPv6 vaddr{};
    madoka::Peer peer = madoka::peer_create(id, vaddr);

    assert(peer.state == madoka::PeerState::Unknown);
    assert(peer.last_seen == 0);

    madoka::peer_update_state(&peer, madoka::PeerState::Connecting);
    assert(peer.state == madoka::PeerState::Connecting);
    assert(peer.last_seen == 0);

    madoka::peer_update_state(&peer, madoka::PeerState::Connected, 15000);
    assert(peer.state == madoka::PeerState::Connected);
    assert(peer.last_seen == 15000);

    madoka::peer_update_state(&peer, madoka::PeerState::Disconnected);
    assert(peer.state == madoka::PeerState::Disconnected);
    assert(peer.last_seen == 15000);

    std::cout << "  -> PASSED: Peer state and timestamp updated correctly.\n";
}

void test_peer_liveness() {
    std::cout << "[TEST] 4. Testing peer liveness (5000ms timeout)...\n";

    madoka::NodeId id{};
    madoka::IPv6 vaddr{};
    madoka::Peer peer = madoka::peer_create(id, vaddr);

    assert(!madoka::peer_is_alive(peer, 10000));

    madoka::peer_update_state(&peer, madoka::PeerState::Connected, 0);
    assert(!madoka::peer_is_alive(peer, 10000));

    madoka::peer_update_state(&peer, madoka::PeerState::Connected, 10000);
    assert(madoka::peer_is_alive(peer, 10000));
    assert(madoka::peer_is_alive(peer, 12000));
    assert(madoka::peer_is_alive(peer, 15000));
    assert(!madoka::peer_is_alive(peer, 15001));
    assert(!madoka::peer_is_alive(peer, 9999));

    std::cout
        << "  -> PASSED: Liveness evaluation correctly honors 5s contract.\n";
}

void test_peer_diagnostics() {
    std::cout << "[TEST] 5. Testing peer state string conversions...\n";

    assert(madoka::to_string(madoka::PeerState::Unknown) == "Unknown");
    assert(madoka::to_string(madoka::PeerState::Connecting) == "Connecting");
    assert(madoka::to_string(madoka::PeerState::Connected) == "Connected");
    assert(madoka::to_string(madoka::PeerState::Disconnected) ==
           "Disconnected");

    std::cout << "  -> PASSED: Peer diagnostic strings are accurate.\n";
}

int main() {
    std::cout << "========================================\n"
              << "Running Madoka Peer Unit Tests (DoD)\n"
              << "========================================\n";

    test_peer_create();
    test_peer_equality();
    test_peer_state_update();
    test_peer_liveness();
    test_peer_diagnostics();

    std::cout << "\nAll peer unit tests passed successfully!\n";
    return 0;
}
