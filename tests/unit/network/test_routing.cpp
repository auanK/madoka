#include "network/routing.hpp"

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

void test_routing_empty_table() {
    std::cout << "[TEST] 1. Testing empty route table initialization...\n";

    madoka::RouteTable table = madoka::routing_init();
    assert(table.routes.empty());
    assert(madoka::routing_count(table) == 0);

    std::cout << "  -> PASSED: Empty route table correctly initialized.\n";
}

void test_routing_add_and_find() {
    std::cout << "[TEST] 2. Testing adding and querying routes...\n";

    madoka::RouteTable table = madoka::routing_init();
    const madoka::IPv6 dst_c = make_test_ip(0x0c);
    const madoka::NodeId next_hop_b = make_test_id('B');

    const madoka::Route r = madoka::route_create(dst_c, next_hop_b, 1);
    const bool added = madoka::routing_add_route(table, r);
    assert(added);
    assert(madoka::routing_count(table) == 1);

    const madoka::Route* found = madoka::routing_find_route(table, dst_c);
    assert(found != nullptr);
    assert(found->destination == dst_c);
    assert(found->next_hop == next_hop_b);
    assert(found->metric == 1);

    const madoka::IPv6 unknown_dst = make_test_ip(0x99);
    assert(madoka::routing_find_route(table, unknown_dst) == nullptr);

    std::cout << "  -> PASSED: Route addition and lookup verified.\n";
}

void test_routing_metric_and_duplicate_policy() {
    std::cout
        << "[TEST] 3. Testing metric-based update and duplicate policy...\n";

    madoka::RouteTable table = madoka::routing_init();
    const madoka::IPv6 dst_c = make_test_ip(0x0c);
    const madoka::NodeId next_hop_b = make_test_id('B');
    const madoka::NodeId next_hop_d = make_test_id('D');
    const madoka::NodeId next_hop_e = make_test_id('E');

    assert(madoka::routing_add_route(
        table, madoka::route_create(dst_c, next_hop_b, 5)));
    assert(madoka::routing_count(table) == 1);

    assert(madoka::routing_add_route(
        table, madoka::route_create(dst_c, next_hop_d, 3)));
    assert(madoka::routing_count(table) == 1);

    const madoka::Route* updated = madoka::routing_find_route(table, dst_c);
    assert(updated != nullptr);
    assert(updated->next_hop == next_hop_d);
    assert(updated->metric == 3);

    assert(!madoka::routing_add_route(
        table, madoka::route_create(dst_c, next_hop_e, 10)));
    assert(madoka::routing_count(table) == 1);

    assert(!madoka::routing_add_route(
        table, madoka::route_create(dst_c, next_hop_e, 3)));
    assert(madoka::routing_count(table) == 1);

    const madoka::Route* final_route = madoka::routing_find_route(table, dst_c);
    assert(final_route != nullptr);
    assert(final_route->next_hop == next_hop_d);
    assert(final_route->metric == 3);

    std::cout << "  -> PASSED: Better metric replacement and duplicate "
                 "rejection confirmed.\n";
}

void test_routing_remove_and_clear() {
    std::cout << "[TEST] 4. Testing route removal and clearing...\n";

    madoka::RouteTable table = madoka::routing_init();
    const madoka::IPv6 dst1 = make_test_ip(1);
    const madoka::IPv6 dst2 = make_test_ip(2);
    const madoka::NodeId hop = make_test_id('H');

    assert(
        madoka::routing_add_route(table, madoka::route_create(dst1, hop, 1)));
    assert(
        madoka::routing_add_route(table, madoka::route_create(dst2, hop, 2)));
    assert(madoka::routing_count(table) == 2);

    assert(madoka::routing_remove_route(table, dst1));
    assert(madoka::routing_count(table) == 1);
    assert(madoka::routing_find_route(table, dst1) == nullptr);
    assert(madoka::routing_find_route(table, dst2) != nullptr);

    assert(!madoka::routing_remove_route(table, dst1));

    madoka::routing_clear(table);
    assert(madoka::routing_count(table) == 0);
    assert(madoka::routing_find_route(table, dst2) == nullptr);

    std::cout << "  -> PASSED: Route removal and clear operations verified.\n";
}

} // namespace

int main() {
    std::cout << "=== Madoka Mesh Routing Unit Tests ===\n";

    test_routing_empty_table();
    test_routing_add_and_find();
    test_routing_metric_and_duplicate_policy();
    test_routing_remove_and_clear();

    std::cout << "=== All Routing Unit Tests Passed Successfully ===\n";
    return 0;
}
