#include "network/topology.hpp"

#include <cassert>
#include <iostream>

void test_topology_init_and_add() {
    std::cout << "[TEST] 1. Initializing Topology and adding valid peers...\n";

    madoka::Topology topo{};
    madoka::topology_init(&topo);
    assert(madoka::topology_count(topo) == 0);

    madoka::NodeId id1{};
    id1.fill(0x01);
    madoka::IPv6 vaddr1{};
    vaddr1.fill(0xFD);
    vaddr1[15] = 0x01;

    madoka::Peer peer1 = madoka::peer_create(id1, vaddr1, "192.168.1.10:4242");
    std::string err;
    assert(madoka::topology_add_peer(&topo, peer1, &err));
    assert(madoka::topology_count(topo) == 1);

    const madoka::Peer* found_by_id = madoka::topology_find_peer(topo, id1);
    assert(found_by_id != nullptr);
    assert(found_by_id->id == id1);
    assert(found_by_id->endpoint == "192.168.1.10:4242");

    const madoka::Peer* found_by_ip =
        madoka::topology_find_by_address(topo, vaddr1);
    assert(found_by_ip != nullptr);
    assert(found_by_ip->id == id1);

    std::cout
        << "  -> PASSED: Topology successfully stores and indexes peers.\n";
}

void test_topology_duplicate_rejection() {
    std::cout << "[TEST] 2. Rejecting duplicate Node ID registration...\n";

    madoka::Topology topo{};
    madoka::topology_init(&topo);

    madoka::NodeId id{};
    id.fill(0x42);
    madoka::IPv6 vaddr{};
    vaddr.fill(0xFD);

    madoka::Peer peer1 = madoka::peer_create(id, vaddr, "10.0.0.1:5000");
    assert(madoka::topology_add_peer(&topo, peer1));

    madoka::Peer duplicate = madoka::peer_create(
        id, vaddr, "10.0.0.2:6000", madoka::PeerState::Connected);
    std::string err;
    bool added = madoka::topology_add_peer(&topo, duplicate, &err);
    assert(!added);
    assert(!err.empty());
    assert(madoka::topology_count(topo) == 1);

    std::cout << "  -> PASSED: Duplicate Node ID rejected safely.\n";
}

void test_topology_capacity_limit() {
    std::cout << "[TEST] 3. Enforcing 16-peer mesh capacity limit...\n";

    madoka::Topology topo{};
    madoka::topology_init(&topo);

    for (unsigned int i = 0; i < madoka::MAX_TOPOLOGY_PEERS; ++i) {
        madoka::NodeId id{};
        id[0] = static_cast<unsigned char>(i + 1);
        madoka::IPv6 vaddr{};
        vaddr[15] = static_cast<unsigned char>(i + 1);

        madoka::Peer peer = madoka::peer_create(id, vaddr);
        assert(madoka::topology_add_peer(&topo, peer));
    }
    assert(madoka::topology_count(topo) == 16);

    madoka::NodeId overflow_id{};
    overflow_id.fill(0xFF);
    madoka::IPv6 overflow_ip{};
    madoka::Peer overflow_peer = madoka::peer_create(overflow_id, overflow_ip);

    std::string err;
    bool added = madoka::topology_add_peer(&topo, overflow_peer, &err);
    assert(!added);
    assert(!err.empty());
    assert(madoka::topology_count(topo) == 16);

    std::cout
        << "  -> PASSED: Maximum capacity of 16 nodes strictly enforced.\n";
}

void test_topology_state_and_liveness() {
    std::cout << "[TEST] 4. Testing peer state transitions and active neighbor "
                 "count...\n";

    madoka::Topology topo{};
    madoka::topology_init(&topo);

    madoka::NodeId id{};
    id.fill(0x05);
    madoka::IPv6 vaddr{};

    assert(madoka::topology_add_peer(&topo, madoka::peer_create(id, vaddr)));
    assert(madoka::topology_active_neighbors_count(topo, 10000) == 0);

    assert(madoka::topology_update_state(
        &topo, id, madoka::PeerState::Connected, 10000));
    assert(madoka::topology_active_neighbors_count(topo, 12000) == 1);
    assert(madoka::topology_active_neighbors_count(topo, 15000) == 1);
    assert(madoka::topology_active_neighbors_count(topo, 15001) == 0);

    std::cout << "  -> PASSED: State updates and neighbor liveness tracked "
                 "accurately.\n";
}

void test_topology_stale_pruning() {
    std::cout << "[TEST] 5. Pruning stale/inactive neighbors...\n";

    madoka::Topology topo{};
    madoka::topology_init(&topo);

    madoka::NodeId id1{};
    id1[0] = 0x01;
    madoka::NodeId id2{};
    id2[0] = 0x02;
    madoka::IPv6 vaddr{};

    assert(madoka::topology_add_peer(&topo, madoka::peer_create(id1, vaddr)));
    assert(madoka::topology_add_peer(&topo, madoka::peer_create(id2, vaddr)));

    madoka::topology_update_state(
        &topo, id1, madoka::PeerState::Connected, 10000);
    madoka::topology_update_state(
        &topo, id2, madoka::PeerState::Connected, 5000);

    std::size_t pruned = madoka::topology_prune_stale(&topo, 12000, 5000);
    assert(pruned == 1);

    const madoka::Peer* p1 = madoka::topology_find_peer(topo, id1);
    const madoka::Peer* p2 = madoka::topology_find_peer(topo, id2);

    assert(p1->state == madoka::PeerState::Connected);
    assert(p2->state == madoka::PeerState::Disconnected);

    std::cout << "  -> PASSED: Inactive peers pruned to Disconnected state.\n";
}

void test_topology_removal() {
    std::cout << "[TEST] 6. Removing peers from topology...\n";

    madoka::Topology topo{};
    madoka::topology_init(&topo);

    madoka::NodeId id{};
    id.fill(0x09);
    madoka::IPv6 vaddr{};

    assert(madoka::topology_add_peer(&topo, madoka::peer_create(id, vaddr)));
    assert(madoka::topology_count(topo) == 1);

    assert(madoka::topology_remove_peer(&topo, id));
    assert(madoka::topology_count(topo) == 0);
    assert(madoka::topology_find_peer(topo, id) == nullptr);

    assert(!madoka::topology_remove_peer(&topo, id));

    std::cout
        << "  -> PASSED: Peer removal functions safely and cleans entries.\n";
}

int main() {
    std::cout << "========================================\n"
              << "Running Madoka Topology Unit Tests (DoD)\n"
              << "========================================\n";

    test_topology_init_and_add();
    test_topology_duplicate_rejection();
    test_topology_capacity_limit();
    test_topology_state_and_liveness();
    test_topology_stale_pruning();
    test_topology_removal();

    std::cout << "\nAll topology unit tests passed successfully!\n";
    return 0;
}
