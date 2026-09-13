#include "network/forwarding.hpp"

#include <cassert>
#include <iostream>

namespace {

madoka::NodeId make_test_id(char c) {
    madoka::NodeId id{};
    id.fill(static_cast<uint8_t>(c));
    return id;
}

void test_forwarding_engine_multi_hop() {
    std::cout << "[TEST] 5. Testing multi-hop forwarding (A -> B -> C)...\n";

    const madoka::NodeId node_a = make_test_id('A');
    const madoka::NodeId node_b = make_test_id('B');
    const madoka::NodeId node_c = make_test_id('C');

    madoka::RoutingTable table_a = madoka::routing_init();
    assert(madoka::routing_add_route(table_a,
                                     madoka::route_create(node_c, node_b, 2)));
    auto engine_a = madoka::forwarding_init(&table_a, &node_a);

    madoka::RoutingTable table_b = madoka::routing_init();
    assert(madoka::routing_add_route(table_b,
                                     madoka::route_create(node_c, node_c, 1)));
    auto engine_b = madoka::forwarding_init(&table_b, &node_b);

    madoka::RoutingTable table_c = madoka::routing_init();
    auto engine_c = madoka::forwarding_init(&table_c, &node_c);

    bool c_delivered = false;
    std::vector<uint8_t> received_payload;
    madoka::forwarding_set_local_delivery_handler(
        &engine_c, [&](const madoka::DataPacket& pkt) {
            c_delivered = true;
            received_payload = pkt.payload;
        });

    madoka::forwarding_set_transmit_handler(
        &engine_a, [&](const madoka::NodeId& next_hop, madoka::DataPacket pkt) {
            assert(next_hop == node_b);
            madoka::forwarding_forward(&engine_b, &pkt);
        });

    madoka::forwarding_set_transmit_handler(
        &engine_b, [&](const madoka::NodeId& next_hop, madoka::DataPacket pkt) {
            assert(next_hop == node_c);
            madoka::forwarding_forward(&engine_c, &pkt);
        });

    const std::vector<uint8_t> original_payload = {0xCA, 0xFE, 0xBA, 0xBE};
    madoka::DataPacket pkt = madoka::data_packet_create(
        madoka::PacketType::DATA, node_a, node_c, 42, 10, original_payload);

    madoka::forwarding_forward(&engine_a, &pkt);

    assert(c_delivered);
    assert(received_payload == original_payload);
    assert(engine_a.metrics.forwarded_packets == 1);
    assert(engine_b.metrics.forwarded_packets == 1);

    std::cout << "  -> PASSED: Multi-hop packet delivered to C with original "
                 "payload preserved.\n";
}

void test_forwarding_engine_ttl_loop_prevention() {
    std::cout
        << "[TEST] 6. Testing TTL expiration and loop prevention (TTL=1)...\n";

    const madoka::NodeId node_a = make_test_id('A');
    const madoka::NodeId node_b = make_test_id('B');
    const madoka::NodeId node_c = make_test_id('C');

    madoka::RoutingTable table_a = madoka::routing_init();
    assert(madoka::routing_add_route(table_a,
                                     madoka::route_create(node_c, node_b, 1)));
    auto engine = madoka::forwarding_init(&table_a, &node_a);

    bool dropped = false;
    std::string drop_reason;
    madoka::forwarding_set_drop_handler(
        &engine, [&](const madoka::DataPacket&, std::string_view reason) {
            dropped = true;
            drop_reason = reason;
        });

    madoka::DataPacket pkt = madoka::data_packet_create(
        madoka::PacketType::DATA, node_a, node_c, 100, 1, {0x01});

    madoka::forwarding_forward(&engine, &pkt);

    assert(dropped);
    assert(drop_reason == "TTL expired");
    assert(pkt.ttl == 0);
    assert(engine.metrics.ttl_expired_packets == 1);
    assert(engine.metrics.dropped_packets == 1);
    assert(engine.metrics.forwarded_packets == 0);

    std::cout << "  -> PASSED: Packet with TTL=1 dropped with reason 'TTL "
                 "expired'.\n";
}

void test_forwarding_engine_unknown_destination() {
    std::cout << "[TEST] 7. Testing packet drop on unknown destination...\n";

    const madoka::NodeId node_a = make_test_id('A');
    const madoka::NodeId node_unknown = make_test_id('Z');

    madoka::RoutingTable table_a = madoka::routing_init();
    auto engine = madoka::forwarding_init(&table_a, &node_a);

    bool dropped = false;
    madoka::forwarding_set_drop_handler(
        &engine, [&](const madoka::DataPacket&, std::string_view) {
            dropped = true;
        });

    madoka::DataPacket pkt = madoka::data_packet_create(
        madoka::PacketType::DATA, node_a, node_unknown, 101, 10, {0x01});

    madoka::forwarding_forward(&engine, &pkt);

    assert(dropped);
    assert(engine.metrics.unknown_destination_packets == 1);
    assert(engine.metrics.dropped_packets == 1);

    std::cout << "  -> PASSED: Unknown destination correctly dropped.\n";
}

void test_forwarding_engine_artificial_loop_expires() {
    std::cout
        << "[TEST] 8. Testing an artificial route loop expires by TTL...\n";

    const madoka::NodeId node_a = make_test_id('A');
    const madoka::NodeId node_b = make_test_id('B');
    const madoka::NodeId node_c = make_test_id('C');
    madoka::RoutingTable table = madoka::routing_init();
    assert(madoka::routing_add_route(table,
                                     madoka::route_create(node_c, node_b, 1)));
    auto engine = madoka::forwarding_init(&table, &node_a);
    bool dropped = false;
    uint8_t dropped_ttl = 255;
    madoka::forwarding_set_drop_handler(
        &engine, [&](const madoka::DataPacket& p, std::string_view reason) {
            dropped = reason == "TTL expired";
            dropped_ttl = p.ttl;
        });
    madoka::forwarding_set_transmit_handler(
        &engine, [&](const madoka::NodeId&, madoka::DataPacket packet) {
            madoka::forwarding_forward(&engine, &packet);
        });

    auto packet = madoka::data_packet_create(
        madoka::PacketType::DATA, node_a, node_c, 7, 2, {0x01});
    madoka::forwarding_forward(&engine, &packet);
    assert(dropped);
    assert(dropped_ttl == 0);
    assert(engine.metrics.ttl_expired_packets == 1);

    std::cout
        << "  -> PASSED: Artificial routing loop terminates at TTL zero.\n";
}

void test_forwarding_engine_control_plane_integration() {
    std::cout << "[TEST] 9. Testing Control Plane -> Data Plane dynamic route "
                 "update...\n";

    const madoka::NodeId node_a = make_test_id('A');
    const madoka::NodeId node_b = make_test_id('B');
    const madoka::NodeId node_c = make_test_id('C');
    const madoka::NodeId node_d = make_test_id('D');

    madoka::RoutingTable table_a = madoka::routing_init();

    assert(madoka::routing_add_route(table_a,
                                     madoka::route_create(node_c, node_b, 5)));

    auto engine = madoka::forwarding_init(&table_a, &node_a);

    madoka::NodeId forwarded_next_hop{};
    madoka::forwarding_set_transmit_handler(
        &engine,
        [&](const madoka::NodeId& next_hop, const madoka::DataPacket&) {
            forwarded_next_hop = next_hop;
        });

    madoka::DataPacket pkt1 = madoka::data_packet_create(
        madoka::PacketType::DATA, node_a, node_c, 1, 10, {0x01});
    madoka::forwarding_forward(&engine, &pkt1);
    assert(forwarded_next_hop == node_b);

    assert(madoka::routing_add_route(table_a,
                                     madoka::route_create(node_c, node_d, 2)));

    madoka::DataPacket pkt2 = madoka::data_packet_create(
        madoka::PacketType::DATA, node_a, node_c, 2, 10, {0x02});
    madoka::forwarding_forward(&engine, &pkt2);
    assert(forwarded_next_hop == node_d);

    std::cout << "  -> PASSED: Data Plane immediately adopted new route (C via "
                 "D) after Control Plane update.\n";
}

} // namespace

int main() {
    std::cout << "=== Madoka Mesh Packet Forwarding Unit Tests ===\n";

    test_forwarding_engine_multi_hop();
    test_forwarding_engine_ttl_loop_prevention();
    test_forwarding_engine_unknown_destination();
    test_forwarding_engine_artificial_loop_expires();
    test_forwarding_engine_control_plane_integration();

    std::cout
        << "=== All Packet Forwarding Unit Tests Passed Successfully ===\n";
    return 0;
}
