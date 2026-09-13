#include "network/discovery.hpp"
#include "network/route_advertisement.hpp"

#include <cassert>
#include <iostream>

namespace {

madoka::IPv6 make_test_ip(uint8_t b) {
    madoka::IPv6 ip{};
    ip[0] = 0xfd;
    ip[15] = b;
    return ip;
}

madoka::NodeId make_test_id(char c) {
    madoka::NodeId id{};
    id.fill(static_cast<uint8_t>(c));
    return id;
}

void test_neighbor_advertisement() {
    std::cout << "[TEST] 1. Testing Neighbor Advertisement creation...\n";

    const madoka::NodeId node_b = make_test_id('B');
    const madoka::IPv6 ip_b = make_test_ip(0x0b);

    const madoka::Peer peer_b = madoka::peer_create(
        node_b, ip_b, "192.168.1.50:4242", madoka::PeerState::Connected, 1500);

    const madoka::NeighborAdvertisement adv1 =
        madoka::discovery_create_advertisement(peer_b);
    assert(adv1.node_id == node_b);
    assert(adv1.address == ip_b);
    assert(adv1.timestamp == 1500);
    assert(adv1.sequence_number == 0);

    const madoka::NeighborAdvertisement adv2 =
        madoka::discovery_create_advertisement(peer_b, 9999, 42);
    assert(adv2.node_id == node_b);
    assert(adv2.address == ip_b);
    assert(adv2.timestamp == 9999);
    assert(adv2.sequence_number == 42);

    std::cout << "  -> PASSED: Neighbor Advertisement correctly created.\n";
}

void test_route_advertisement() {
    std::cout << "[TEST] 2. Testing Route Advertisement generation...\n";

    const madoka::NodeId node_b = make_test_id('B');
    const madoka::IPv6 ip_c = make_test_ip(0x0c);
    const madoka::NodeId hop_c = make_test_id('C');

    madoka::RouteTable table_b = madoka::routing_init();
    assert(madoka::routing_add_route(
        table_b, madoka::route_create(ip_c, hop_c, 1, 2000)));

    const madoka::RouteAdvertisement adv =
        madoka::route_create_advertisement(node_b, table_b, 100);

    assert(adv.sender == node_b);
    assert(adv.sequence_number == 100);
    assert(adv.routes.size() == 1);
    assert(adv.routes[0].destination == ip_c);
    assert(adv.routes[0].next_hop == hop_c);
    assert(adv.routes[0].metric == 1);
    assert(adv.routes[0].last_update == 2000);

    std::cout << "  -> PASSED: Route Advertisement successfully generated.\n";
}

void test_discovery_sequence_versioning() {
    std::cout << "[TEST] 3. Testing Neighbor Discovery sequence control...\n";

    madoka::Topology topo;
    madoka::topology_init(&topo);

    const madoka::NodeId node_b = make_test_id('B');
    const madoka::IPv6 ip_b = make_test_ip(0x0b);

    uint64_t last_known_seq = 0;

    const madoka::NeighborAdvertisement adv_seq10{
        .node_id = node_b,
        .address = ip_b,
        .timestamp = 1000,
        .sequence_number = 10,
    };
    assert(madoka::discovery_process_advertisement(
        &topo, adv_seq10, &last_known_seq, 1000));
    assert(last_known_seq == 10);
    assert(madoka::topology_count(topo) == 1);

    assert(!madoka::discovery_process_advertisement(
        &topo, adv_seq10, &last_known_seq, 1050));

    const madoka::NeighborAdvertisement adv_seq5{
        .node_id = node_b,
        .address = ip_b,
        .timestamp = 500,
        .sequence_number = 5,
    };
    assert(!madoka::discovery_process_advertisement(
        &topo, adv_seq5, &last_known_seq, 1100));
    assert(last_known_seq == 10);

    const madoka::NeighborAdvertisement adv_seq20{
        .node_id = node_b,
        .address = ip_b,
        .timestamp = 2000,
        .sequence_number = 20,
    };
    assert(madoka::discovery_process_advertisement(
        &topo, adv_seq20, &last_known_seq, 2000));
    assert(last_known_seq == 20);

    std::cout << "  -> PASSED: Stale advertisements ignored; newer accepted.\n";
}

} // namespace

int main() {
    std::cout << "=== Madoka Mesh Discovery Unit Tests ===\n";

    test_neighbor_advertisement();
    test_route_advertisement();
    test_discovery_sequence_versioning();

    std::cout << "=== All Discovery Unit Tests Passed Successfully ===\n";
    return 0;
}
