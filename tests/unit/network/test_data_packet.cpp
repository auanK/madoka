#include "network/data_packet.hpp"
#include "network/data_serialization.hpp"

#include <cassert>
#include <iostream>

namespace {

madoka::NodeId make_test_id(char c) {
    madoka::NodeId id{};
    id.fill(static_cast<uint8_t>(c));
    return id;
}

void test_data_packet_creation() {
    std::cout << "[TEST] 1. Testing DataPacket creation and validation...\n";

    const madoka::NodeId node_a = make_test_id('A');
    const madoka::NodeId node_b = make_test_id('B');
    const std::vector<uint8_t> payload = {0x01, 0x02, 0x03, 0x04};

    const madoka::DataPacket packet = madoka::data_packet_create(
        madoka::PacketType::DATA, node_a, node_b, 1001, 32, payload);

    assert(packet.is_valid());
    assert(packet.type == madoka::PacketType::DATA);
    assert(packet.source == node_a);
    assert(packet.destination == node_b);
    assert(packet.packet_id == 1001);
    assert(packet.ttl == 32);
    assert(packet.payload == payload);
    assert(madoka::to_string(packet.type) == "DATA");

    const madoka::DataPacket ack = madoka::data_packet_create(
        madoka::PacketType::ACK, node_b, node_a, 1001, 64, {});
    assert(ack.is_valid());
    assert(ack.type == madoka::PacketType::ACK);
    assert(ack.payload.empty());
    assert(madoka::to_string(ack.type) == "ACK");

    std::cout << "  -> PASSED: DataPacket creation and fields verified.\n";
}

void test_data_packet_serialization_roundtrip() {
    std::cout << "[TEST] 2. Testing DataPacket serialize -> deserialize "
                 "roundtrip...\n";

    const madoka::NodeId node_a = make_test_id('A');
    const madoka::NodeId node_c = make_test_id('C');
    const std::vector<uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};

    const madoka::DataPacket original = madoka::data_packet_create(
        madoka::PacketType::DATA, node_a, node_c, 987654321ULL, 45, payload);

    const std::vector<uint8_t> encoded = madoka::serialize_packet(original);
    assert(encoded.size() == madoka::DATA_PACKET_HEADER_SIZE + payload.size());

    madoka::DataPacket decoded{};
    std::string err;
    const bool ok = madoka::deserialize_packet(encoded, &decoded, &err);
    assert(ok);
    assert(err.empty());
    assert(decoded == original);

    const madoka::DataPacket decoded2 = madoka::deserialize_packet(encoded);
    assert(decoded2 == original);

    std::cout << "  -> PASSED: Roundtrip preserves all packet fields and "
                 "payload exactly.\n";
}

void test_data_packet_ttl_preservation() {
    std::cout << "[TEST] 3. Testing TTL preservation across serialization...\n";

    const madoka::NodeId node_a = make_test_id('A');
    const madoka::NodeId node_b = make_test_id('B');

    for (uint8_t test_ttl :
         {uint8_t{1}, uint8_t{7}, uint8_t{64}, uint8_t{255}}) {
        const madoka::DataPacket original =
            madoka::data_packet_create(madoka::PacketType::DATA,
                                       node_a,
                                       node_b,
                                       42,
                                       test_ttl,
                                       {0x11, 0x22});

        const std::vector<uint8_t> encoded = madoka::serialize_packet(original);
        const madoka::DataPacket decoded = madoka::deserialize_packet(encoded);

        assert(decoded.is_valid());
        assert(decoded.ttl == test_ttl);
    }

    std::cout
        << "  -> PASSED: TTL faithfully preserved for all boundary values.\n";
}

void test_data_packet_malformed_rejection() {
    std::cout
        << "[TEST] 4. Testing rejection of malformed or truncated buffers...\n";

    const std::vector<uint8_t> too_small(50, 0xFF);
    madoka::DataPacket out{};
    std::string error;
    assert(!madoka::deserialize_packet(too_small, &out, &error));
    assert(!error.empty());

    const madoka::NodeId node_a = make_test_id('A');
    const madoka::NodeId node_b = make_test_id('B');
    madoka::DataPacket valid = madoka::data_packet_create(
        madoka::PacketType::DATA, node_a, node_b, 1, 10, {0xAA});
    std::vector<uint8_t> corrupted = madoka::serialize_packet(valid);
    corrupted[0] = 42;

    assert(!madoka::deserialize_packet(corrupted, &out, &error));
    assert(!madoka::deserialize_packet(corrupted).is_valid());

    corrupted = madoka::serialize_packet(valid);
    corrupted.pop_back();
    assert(!madoka::deserialize_packet(corrupted, &out, &error));

    corrupted = madoka::serialize_packet(valid);
    corrupted.push_back(0xBB);
    assert(!madoka::deserialize_packet(corrupted, &out, &error));

    std::cout << "  -> PASSED: Defensive validation safely rejects corrupted "
                 "buffers.\n";
}

void test_ipv6_mtu_roundtrip() {
    std::cout
        << "[TEST] 5. Testing raw IPv6 DataPacket roundtrip at MTU 1280...\n";

    madoka::NodeId node_a = make_test_id('A');
    madoka::NodeId node_b = make_test_id('B');
    std::vector<uint8_t> ipv6(1280, 0);
    ipv6[0] = 0x60;
    ipv6[4] = static_cast<uint8_t>((1280 - 40) >> 8);
    ipv6[5] = static_cast<uint8_t>(1280 - 40);
    ipv6[24] = 0xFD;

    const auto original = madoka::data_packet_create(
        madoka::PacketType::DATA, node_a, node_b, 7, 64, false, 0, ipv6);
    const auto encoded = madoka::serialize_packet(original);
    assert(encoded.size() == madoka::DATA_PACKET_HEADER_SIZE + 1280);

    madoka::DataPacket decoded{};
    assert(madoka::deserialize_packet(encoded, &decoded));
    assert(decoded.payload == ipv6);
    assert(decoded.source == node_a && decoded.destination == node_b);
    assert(decoded.ttl == 64 && !decoded.requires_ack);
    std::cout << "  -> PASSED: 1280-byte raw IPv6 payload preserved exactly.\n";
}

} // namespace

int main() {
    std::cout << "=== Running DataPacket & Serialization Unit Tests ===\n";
    test_data_packet_creation();
    test_data_packet_serialization_roundtrip();
    test_data_packet_ttl_preservation();
    test_data_packet_malformed_rejection();
    test_ipv6_mtu_roundtrip();
    std::cout << "=== All DataPacket tests PASSED ===\n";
    return 0;
}
