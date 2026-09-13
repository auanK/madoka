#include "network/kademlia.hpp"

#include <algorithm>
#include <cassert>
#include <iostream>

using namespace madoka;

void test_kademlia_distance_and_bucket_index() {
    NodeId local{};
    local.fill(0x00);

    assert(kademlia_bucket_index(local, local) == 256);
    auto dist_zero = kademlia_distance(local, local);
    assert(std::all_of(dist_zero.begin(), dist_zero.end(), [](uint8_t b) {
        return b == 0;
    }));

    NodeId max_dist_node{};
    max_dist_node.fill(0x00);
    max_dist_node[0] = 0x80;
    assert(kademlia_bucket_index(local, max_dist_node) == 0);

    NodeId min_dist_node{};
    min_dist_node.fill(0x00);
    min_dist_node[31] = 0x01;
    assert(kademlia_bucket_index(local, min_dist_node) == 255);

    for (std::size_t bit_pos = 0; bit_pos < 256; ++bit_pos) {
        NodeId remote{};
        remote.fill(0x00);
        const std::size_t byte_idx = bit_pos / 8;
        const std::size_t bit_in_byte = bit_pos % 8;
        remote[byte_idx] = static_cast<uint8_t>(1u << (7 - bit_in_byte));

        assert(kademlia_bucket_index(local, remote) == bit_pos);
    }
}

void test_kademlia_table_init_and_counts() {
    KademliaTable table{};
    NodeId local_id{1};
    kademlia_init(&table, local_id);

    assert(table.local_id == local_id);
    assert(kademlia_total_contacts(table) == 0);
    for (const auto& bucket : table.buckets) {
        assert(bucket.contacts.empty());
    }
}

void test_kademlia_insert_and_update() {
    KademliaTable table{};
    NodeId local_id{};
    local_id.fill(0xAA);
    kademlia_init(&table, local_id);

    NodeContact self_contact{.id = local_id};
    assert(!kademlia_insert(table, self_contact));
    assert(kademlia_total_contacts(table) == 0);

    NodeId peer1_id{};
    peer1_id.fill(0xAA);
    peer1_id[31] ^= 0x01;

    NodeContact c1{
        .id = peer1_id,
        .endpoint = "10.0.0.1:9000",
        .last_seen_ms = 1000,
        .rtt_ms = 15,
    };
    assert(kademlia_insert(table, c1));
    assert(kademlia_total_contacts(table) == 1);

    const auto* found = kademlia_find(table, peer1_id);
    assert(found != nullptr);
    assert(found->endpoint == "10.0.0.1:9000");
    assert(found->last_seen_ms == 1000);

    NodeContact c1_updated{
        .id = peer1_id,
        .endpoint = "10.0.0.1:9001",
        .last_seen_ms = 2000,
        .rtt_ms = 10,
    };
    assert(kademlia_insert(table, c1_updated));
    assert(kademlia_total_contacts(table) == 1);

    found = kademlia_find(table, peer1_id);
    assert(found != nullptr);
    assert(found->endpoint == "10.0.0.1:9001");
    assert(found->last_seen_ms == 2000);
}

void test_kademlia_bucket_full_and_eviction() {
    KademliaTable table{};
    NodeId local_id{};
    local_id.fill(0x00);
    kademlia_init(&table, local_id);

    for (uint8_t i = 1; i <= KADEMLIA_K; ++i) {
        NodeId pid{};
        pid.fill(0x00);
        pid[0] = 0x80;
        pid[31] = i;

        NodeContact c{
            .id = pid,
            .last_seen_ms = i,
        };
        assert(kademlia_insert(table, c));
    }
    assert(kademlia_total_contacts(table) == KADEMLIA_K);

    const auto& bucket0 = table.buckets[0];
    assert(bucket0.contacts.size() == KADEMLIA_K);
    const NodeId oldest_id = bucket0.contacts.front().id;

    NodeId pid21{};
    pid21.fill(0x00);
    pid21[0] = 0x80;
    pid21[31] = 21;
    NodeContact c21{.id = pid21, .last_seen_ms = 21};

    bool ping_called = false;
    bool inserted = kademlia_insert(table, c21, [&](const NodeContact& oldest) {
        ping_called = true;
        assert(oldest.id == oldest_id);
        return true;
    });
    assert(ping_called);
    assert(!inserted);
    assert(bucket0.contacts.size() == KADEMLIA_K);
    assert(bucket0.contacts.back().id == oldest_id);

    ping_called = false;
    const NodeId next_oldest = bucket0.contacts.front().id;
    inserted = kademlia_insert(table, c21, [&](const NodeContact& oldest) {
        ping_called = true;
        assert(oldest.id == next_oldest);
        return false;
    });
    assert(ping_called);
    assert(inserted);
    assert(bucket0.contacts.size() == KADEMLIA_K);
    assert(kademlia_find(table, next_oldest) == nullptr);
    assert(bucket0.contacts.back().id == pid21);
}

void test_kademlia_find_closest() {
    KademliaTable table{};
    NodeId local_id{};
    local_id.fill(0x00);
    kademlia_init(&table, local_id);

    for (uint8_t i = 1; i <= 10; ++i) {
        NodeId pid{};
        pid.fill(0x00);
        pid[31] = i * 10;
        NodeContact c{.id = pid};
        assert(kademlia_insert(table, c));
    }

    NodeId target{};
    target.fill(0x00);
    target[31] = 25;

    auto closest = kademlia_find_closest(table, target, 5);
    assert(closest.size() == 5);

    auto distance_cmp = [&](const NodeContact& a, const NodeContact& b) {
        for (std::size_t i = 0; i < 32; ++i) {
            const uint8_t da = a.id[i] ^ target[i];
            const uint8_t db = b.id[i] ^ target[i];
            if (da != db) {
                return da < db;
            }
        }
        return false;
    };

    for (std::size_t i = 0; i < closest.size() - 1; ++i) {
        assert(!distance_cmp(closest[i + 1], closest[i]));
    }
}

void test_kademlia_remove_and_find() {
    KademliaTable table{};
    NodeId local_id{1};
    kademlia_init(&table, local_id);

    NodeId p1{2};
    NodeContact c1{.id = p1};
    assert(kademlia_insert(table, c1));
    assert(kademlia_find(table, p1) != nullptr);

    assert(kademlia_remove(table, p1));
    assert(kademlia_find(table, p1) == nullptr);
    assert(!kademlia_remove(table, p1));
}

int main() {
    test_kademlia_distance_and_bucket_index();
    test_kademlia_table_init_and_counts();
    test_kademlia_insert_and_update();
    test_kademlia_bucket_full_and_eviction();
    test_kademlia_find_closest();
    test_kademlia_remove_and_find();

    std::cout << "All Kademlia core unit tests passed successfully.\n";
    return 0;
}
