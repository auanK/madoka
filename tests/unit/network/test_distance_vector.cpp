#include "network/distance_vector.hpp"
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

void test_distance_vector_route_learning() {
    std::cout << "[TEST] 1. Testing dynamic route learning (A - B - C)...\n";

    const madoka::NodeId node_b = make_test_id('B');
    const madoka::IPv6 ip_c = make_test_ip(0x0c);

    madoka::RouteTable table_a = madoka::routing_init();

    const madoka::RouteAdvertisement adv{
        .sender = node_b,
        .sequence_number = 1,
        .routes = {madoka::route_create(ip_c, node_b, 1, 1000)},
    };

    madoka::distance_vector_update(table_a, node_b, adv, 1000);

    assert(madoka::routing_count(table_a) == 1);
    const madoka::Route* learned = madoka::routing_find_route(table_a, ip_c);
    assert(learned != nullptr);
    assert(learned->destination == ip_c);
    assert(learned->next_hop == node_b);
    assert(learned->metric == 2);
    assert(learned->last_update == 1000);

    std::cout
        << "  -> PASSED: Route to C dynamically learned via B with metric 2.\n";
}

void test_distance_vector_better_route_wins() {
    std::cout << "[TEST] 2. Testing that a better metric route replaces "
                 "existing...\n";

    const madoka::NodeId node_b = make_test_id('B');
    const madoka::NodeId node_d = make_test_id('D');
    const madoka::IPv6 ip_c = make_test_ip(0x0c);

    madoka::RouteTable table = madoka::routing_init();

    assert(madoka::routing_add_route(
        table, madoka::route_create(ip_c, node_b, 5, 500)));

    const madoka::RouteAdvertisement adv_d{
        .sender = node_d,
        .sequence_number = 1,
        .routes = {madoka::route_create(ip_c, node_d, 1, 1200)},
    };

    madoka::distance_vector_update(table, node_d, adv_d, 1200);

    assert(madoka::routing_count(table) == 1);
    const madoka::Route* r = madoka::routing_find_route(table, ip_c);
    assert(r != nullptr);
    assert(r->next_hop == node_d);
    assert(r->metric == 2);
    assert(r->last_update == 1200);

    std::cout
        << "  -> PASSED: Better route (metric 2 via D) replaced worse route.\n";
}

void test_distance_vector_worse_route_ignored() {
    std::cout << "[TEST] 3. Testing that a worse metric route is ignored...\n";

    const madoka::NodeId node_b = make_test_id('B');
    const madoka::NodeId node_d = make_test_id('D');
    const madoka::IPv6 ip_c = make_test_ip(0x0c);

    madoka::RouteTable table = madoka::routing_init();

    assert(madoka::routing_add_route(
        table, madoka::route_create(ip_c, node_b, 2, 800)));

    const madoka::RouteAdvertisement adv_d{
        .sender = node_d,
        .sequence_number = 1,
        .routes = {madoka::route_create(ip_c, node_d, 6, 1500)},
    };

    madoka::distance_vector_update(table, node_d, adv_d, 1500);

    assert(madoka::routing_count(table) == 1);
    const madoka::Route* r = madoka::routing_find_route(table, ip_c);
    assert(r != nullptr);
    assert(r->next_hop == node_b);
    assert(r->metric == 2);
    assert(r->last_update == 800);

    std::cout
        << "  -> PASSED: Worse route from D (metric 7) ignored; kept B.\n";
}

void test_distance_vector_route_aging() {
    std::cout << "[TEST] 4. Testing route expiration (aging)...\n";

    const madoka::NodeId node_b = make_test_id('B');
    const madoka::IPv6 ip_c = make_test_ip(0x0c);
    const madoka::IPv6 ip_d = make_test_ip(0x0d);

    madoka::RouteTable table = madoka::routing_init();

    assert(madoka::routing_add_route(
        table, madoka::route_create(ip_c, node_b, 2, 100)));

    assert(madoka::routing_add_route(
        table, madoka::route_create(ip_d, node_b, 3, 180)));

    assert(madoka::routing_count(table) == 2);

    madoka::routing_expire_routes(table, 200, 60);

    assert(madoka::routing_count(table) == 1);
    assert(madoka::routing_find_route(table, ip_c) == nullptr);
    assert(madoka::routing_find_route(table, ip_d) != nullptr);

    madoka::routing_expire_routes(table, 250, 60);
    assert(madoka::routing_count(table) == 0);

    std::cout << "  -> PASSED: Stale routes properly expired and pruned.\n";
}

void test_distance_vector_sequence_control() {
    std::cout
        << "[TEST] 5. Testing sequence number control on route updates...\n";

    const madoka::NodeId node_b = make_test_id('B');
    const madoka::IPv6 ip_c = make_test_ip(0x0c);

    madoka::RouteTable table = madoka::routing_init();
    uint64_t last_seq = 0;

    const madoka::RouteAdvertisement adv10{
        .sender = node_b,
        .sequence_number = 10,
        .routes = {madoka::route_create(ip_c, node_b, 1, 1000)},
    };
    assert(madoka::distance_vector_update(
        table, node_b, adv10, 1000, 1, &last_seq));
    assert(last_seq == 10);
    assert(madoka::routing_count(table) == 1);

    const madoka::RouteAdvertisement adv5{
        .sender = node_b,
        .sequence_number = 5,
        .routes = {madoka::route_create(ip_c, node_b, 1, 1100)},
    };
    assert(!madoka::distance_vector_update(
        table, node_b, adv5, 1100, 1, &last_seq));
    assert(last_seq == 10);

    const madoka::RouteAdvertisement adv20{
        .sender = node_b,
        .sequence_number = 20,
        .routes = {madoka::route_create(ip_c, node_b, 1, 1200)},
    };
    assert(madoka::distance_vector_update(
        table, node_b, adv20, 1200, 1, &last_seq));
    assert(last_seq == 20);

    std::cout << "  -> PASSED: Stale advertisements dropped by sequence "
                 "ordering.\n";
}

void test_distance_vector_split_horizon() {
    std::cout << "[TEST] 6. Testing Split Horizon route generation...\n";

    const madoka::NodeId node_a = make_test_id('A');
    const madoka::NodeId node_b = make_test_id('B');
    const madoka::NodeId node_c = make_test_id('C');
    const madoka::IPv6 ip_c = make_test_ip(0x0c);
    const madoka::IPv6 ip_d = make_test_ip(0x0d);

    madoka::RouteTable table_a = madoka::routing_init();
    madoka::routing_add_route(table_a,
                              madoka::route_create(ip_c, node_b, 2, 1000));
    madoka::routing_add_route(table_a,
                              madoka::route_create(ip_d, node_c, 3, 1000));

    const madoka::RouteAdvertisement adv = madoka::route_create_advertisement(
        node_a, table_a, 1, node_b, madoka::SplitHorizonMode::SplitHorizon);

    assert(adv.routes.size() == 1);
    assert(adv.routes[0].destination == ip_d);
    assert(adv.routes[0].next_hop == node_c);

    std::cout
        << "  -> PASSED: Split Horizon successfully suppresses reverse path.\n";
}

void test_distance_vector_poison_reverse() {
    std::cout << "[TEST] 7. Testing Poison Reverse route generation and "
                 "handling...\n";

    const madoka::NodeId node_a = make_test_id('A');
    const madoka::NodeId node_b = make_test_id('B');
    const madoka::IPv6 ip_c = make_test_ip(0x0c);

    madoka::RouteTable table_a = madoka::routing_init();
    madoka::routing_add_route(table_a,
                              madoka::route_create(ip_c, node_b, 2, 1000));

    const madoka::RouteAdvertisement adv = madoka::route_create_advertisement(
        node_a, table_a, 1, node_b, madoka::SplitHorizonMode::PoisonReverse);

    assert(adv.routes.size() == 1);
    assert(adv.routes[0].destination == ip_c);
    assert(adv.routes[0].metric == madoka::ROUTE_METRIC_INFINITY);

    madoka::RouteTable table_b = madoka::routing_init();
    madoka::routing_add_route(table_b,
                              madoka::route_create(ip_c, node_a, 2, 1000));

    madoka::distance_vector_update(table_b, node_a, adv, 1500);

    const madoka::Route* rb = madoka::routing_find_route(table_b, ip_c);
    assert(rb != nullptr);
    assert(rb->metric == madoka::ROUTE_METRIC_INFINITY);

    std::cout
        << "  -> PASSED: Poison Reverse generated and handled correctly.\n";
}

void test_distance_vector_deterministic_tie_breaking() {
    std::cout
        << "[TEST] 8. Testing deterministic equal-metric tie-breaking...\n";

    const madoka::NodeId node_b = make_test_id('B');
    const madoka::NodeId node_c = make_test_id('C');
    const madoka::NodeId node_d = make_test_id('D');
    const madoka::IPv6 ip_d = make_test_ip(0x0d);

    const auto advertisement = [&](const madoka::NodeId& sender) {
        return madoka::RouteAdvertisement{
            .sender = sender,
            .generation = 1,
            .sequence_number = 1,
            .routes = {
                madoka::route_create(ip_d, madoka::NodeId{}, 1, 0, node_d)}};
    };

    madoka::RouteTable first = madoka::routing_init();
    madoka::RouteOriginStates first_versions;
    assert(madoka::distance_vector_update(
        first, node_c, advertisement(node_c), 100, 1, &first_versions));
    assert(madoka::distance_vector_update(
        first, node_b, advertisement(node_b), 101, 1, &first_versions));

    madoka::RouteTable second = madoka::routing_init();
    madoka::RouteOriginStates second_versions;
    assert(madoka::distance_vector_update(
        second, node_b, advertisement(node_b), 100, 1, &second_versions));
    assert(madoka::distance_vector_update(
        second, node_c, advertisement(node_c), 101, 1, &second_versions));

    const auto* first_route = madoka::routing_find_route(first, node_d);
    const auto* second_route = madoka::routing_find_route(second, node_d);
    assert(first_route != nullptr && second_route != nullptr);
    assert(first_route->next_hop == node_b);
    assert(second_route->next_hop == node_b);

    std::cout << "  -> PASSED: Equal metrics converge on the same next hop.\n";
}

void test_distance_vector_generation_sequence() {
    std::cout
        << "[TEST] 9. Testing per-origin generation and sequence ordering...\n";

    const madoka::NodeId node_c = make_test_id('C');
    const madoka::NodeId node_d = make_test_id('D');
    const madoka::IPv6 ip_d = make_test_ip(0x0d);
    const auto make_advertisement = [&](uint64_t generation,
                                        uint64_t sequence) {
        return madoka::RouteAdvertisement{
            .sender = node_c,
            .generation = generation,
            .sequence_number = sequence,
            .routes = {
                madoka::route_create(ip_d, madoka::NodeId{}, 1, 0, node_d)}};
    };

    madoka::RouteTable table = madoka::routing_init();
    madoka::RouteOriginStates versions;
    assert(madoka::distance_vector_update(
        table, node_c, make_advertisement(5, 10), 100, 1, &versions));
    assert(!madoka::distance_vector_update(
        table, node_c, make_advertisement(5, 10), 101, 1, &versions));
    assert(!madoka::distance_vector_update(
        table, node_c, make_advertisement(5, 9), 102, 1, &versions));
    assert(!madoka::distance_vector_update(
        table, node_c, make_advertisement(4, 999), 103, 1, &versions));
    assert(madoka::distance_vector_update(
        table, node_c, make_advertisement(6, 1), 104, 1, &versions));
    assert(versions.at(node_c).generation == 6);
    assert(versions.at(node_c).sequence == 1);

    std::cout << "  -> PASSED: Duplicate, stale, old-generation and restart "
                 "updates are ordered correctly.\n";
}

void test_distance_vector_refresh_is_not_a_route_change() {
    std::cout << "[TEST] 10. Testing unchanged route refresh...\n";

    const madoka::NodeId node_b = make_test_id('B');
    const madoka::NodeId node_c = make_test_id('C');
    const madoka::IPv6 ip_c = make_test_ip(0x0c);
    madoka::RouteTable table = madoka::routing_init();
    madoka::RouteOriginStates versions;

    const auto advertisement = [&](uint64_t sequence) {
        return madoka::RouteAdvertisement{
            .sender = node_b,
            .generation = 1,
            .sequence_number = sequence,
            .routes = {madoka::route_create(ip_c, {}, 1, 0, node_c)},
        };
    };

    bool changed = false;
    assert(madoka::distance_vector_update(
        table, node_b, advertisement(1), 100, 1, &versions, &changed));
    assert(changed);
    assert(table.routes[0].last_update == 100);

    assert(madoka::distance_vector_update(
        table, node_b, advertisement(2), 200, 1, &versions, &changed));
    assert(!changed);
    assert(table.routes[0].last_update == 200);

    assert(madoka::distance_vector_update(
        table,
        node_b,
        madoka::RouteAdvertisement{
            .sender = node_b, .generation = 1, .sequence_number = 3},
        300,
        1,
        &versions,
        &changed));
    assert(changed);
    assert(table.routes.empty());

    std::cout << "  -> PASSED: Refresh updates age without triggering a "
                 "topology change, while withdrawal does.\n";
}

void test_route_advertisement_identity_validation() {
    std::cout << "[TEST] 11. Testing route NodeID to IPv6 validation...\n";

    const madoka::NodeId node_c = make_test_id('C');
    madoka::IPv6 network{};
    network[0] = 0xfd;
    const auto valid = madoka::virtual_address(network, node_c);
    madoka::RouteAdvertisement advertisement{
        .sender = node_c,
        .generation = 1,
        .sequence_number = 1,
        .routes = {
            madoka::route_create(valid, madoka::NodeId{}, 1, 0, node_c)}};
    std::string error;
    assert(
        madoka::validate_route_advertisement(advertisement, network, &error));
    advertisement.routes[0].destination[15] ^= 1;
    assert(
        !madoka::validate_route_advertisement(advertisement, network, &error));

    std::cout << "  -> PASSED: Inconsistent NodeID and IPv6 are rejected.\n";
}

} // namespace

int main() {
    std::cout << "=== Madoka Mesh Distance Vector Unit Tests ===\n";

    test_distance_vector_route_learning();
    test_distance_vector_better_route_wins();
    test_distance_vector_worse_route_ignored();
    test_distance_vector_route_aging();
    test_distance_vector_sequence_control();
    test_distance_vector_split_horizon();
    test_distance_vector_poison_reverse();
    test_distance_vector_deterministic_tie_breaking();
    test_distance_vector_generation_sequence();
    test_distance_vector_refresh_is_not_a_route_change();
    test_route_advertisement_identity_validation();

    std::cout << "=== All Distance Vector Unit Tests Passed Successfully ===\n";
    return 0;
}
