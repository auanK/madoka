#include "network/heartbeat.hpp"
#include "network/peer.hpp"
#include "network/topology.hpp"

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

void test_heartbeat_active_neighbor_update() {
    std::cout
        << "[TEST] 1. Testing active neighbor update on HELLO reception...\n";

    madoka::Topology topo;
    madoka::topology_init(&topo);

    const madoka::NodeId node_b = make_test_id('B');
    const madoka::IPv6 ip_b = make_test_ip(0x0b);

    madoka::Peer peer_b = madoka::peer_create(
        node_b, ip_b, "10.0.0.2:4242", madoka::PeerState::Unknown, 1000);
    assert(madoka::topology_add_peer(&topo, peer_b));

    madoka::Peer* p = madoka::topology_find_peer(&topo, node_b);
    assert(p != nullptr);
    assert(p->state == madoka::PeerState::Unknown);
    assert(p->last_seen == 1000);

    const madoka::HelloMessage hello =
        madoka::heartbeat_create_hello(node_b, 2500);
    const bool processed = madoka::heartbeat_process_hello(&topo, hello);
    assert(processed);

    assert(p->state == madoka::PeerState::Connected);
    assert(p->last_seen == 2500);

    const madoka::NodeId node_x = make_test_id('X');
    const madoka::HelloMessage hello_x =
        madoka::heartbeat_create_hello(node_x, 3000);
    assert(!madoka::heartbeat_process_hello(&topo, hello_x));

    std::cout << "  -> PASSED: Peer state updated to Connected and last_seen "
                 "refreshed.\n";
}

void test_heartbeat_neighbor_expiration() {
    std::cout << "[TEST] 2. Testing neighbor timeout expiration without "
                 "heartbeat...\n";

    madoka::Topology topo;
    madoka::topology_init(&topo);

    const madoka::NodeId node_b = make_test_id('B');
    const madoka::IPv6 ip_b = make_test_ip(0x0b);

    madoka::Peer peer_b = madoka::peer_create(
        node_b, ip_b, "10.0.0.2:4242", madoka::PeerState::Connected, 1000);
    assert(madoka::topology_add_peer(&topo, peer_b));

    assert(madoka::peer_is_alive(peer_b, 3000, 5000));
    assert(madoka::topology_active_neighbors_count(topo, 3000, 5000) == 1);

    const madoka::Peer* p = madoka::topology_find_peer(topo, node_b);
    assert(p != nullptr);
    assert(!madoka::peer_is_alive(*p, 7000, 5000));
    assert(madoka::topology_active_neighbors_count(topo, 7000, 5000) == 0);

    const std::size_t pruned = madoka::topology_prune_stale(&topo, 7000, 5000);
    assert(pruned == 1);
    assert(p->state == madoka::PeerState::Disconnected);

    std::cout
        << "  -> PASSED: Stale neighbor expired and pruned as expected.\n";
}

} // namespace

int main() {
    std::cout << "=== Madoka Mesh Heartbeat Unit Tests ===\n";

    test_heartbeat_active_neighbor_update();
    test_heartbeat_neighbor_expiration();

    std::cout << "=== All Heartbeat Unit Tests Passed Successfully ===\n";
    return 0;
}
