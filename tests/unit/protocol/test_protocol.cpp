#include "protocol/codec.hpp"
#include "protocol/message.hpp"

#include <cassert>
#include <iostream>
#include <vector>

void test_hello_encode() {
    std::cout << "[TEST] 1. Creating HELLO message and checking encode()...\n";

    madoka::Message hello_empty{.type = madoka::MessageType::HELLO};
    std::vector<uint8_t> encoded_empty = madoka::message_encode(hello_empty);

    const std::vector<uint8_t> expected_empty = {0x01, 0x01, 0x00, 0x00};
    assert(encoded_empty == expected_empty);

    const std::vector<uint8_t> payload = {0xDE, 0xAD, 0xBE, 0xEF};
    madoka::Message hello_with_data{.type = madoka::MessageType::Hello,
                                    .payload = payload};
    assert(hello_with_data.payload.size() == 4);
    std::vector<uint8_t> encoded_with_data =
        madoka::message_encode(hello_with_data);

    const std::vector<uint8_t> expected_with_data = {
        0x01, 0x01, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF};
    assert(encoded_with_data == expected_with_data);

    madoka::Message decoded_hello{};
    bool ok = madoka::message_decode(encoded_with_data, &decoded_hello);
    assert(ok);
    assert(decoded_hello == hello_with_data);
    assert(decoded_hello.type == madoka::MessageType::Hello);

    std::cout << "  -> PASSED: HELLO encode generates exact expected "
                 "big-endian bytes.\n";
}

void test_round_trip() {
    std::cout
        << "[TEST] 2. Testing round-trip (Message -> bytes -> Message)...\n";

    {
        madoka::Message original{.type = madoka::MessageType::Hello,
                                 .payload = {0x10, 0x20, 0x30}};
        auto bytes = madoka::message_encode(original);
        madoka::Message decoded{};
        bool ok = madoka::message_decode(bytes, &decoded);
        assert(ok);
        assert(decoded == original);
        assert(decoded.version == 1);
        assert(decoded.type == madoka::MessageType::Hello);
        assert(decoded.payload == original.payload);
    }

    {
        madoka::Message original{.type = madoka::MessageType::KEEPALIVE};
        auto bytes = madoka::message_encode(original);
        madoka::Message decoded{};
        bool ok = madoka::message_decode(bytes, &decoded);
        assert(ok);
        assert(decoded == original);
        assert(decoded.version == 1);
        assert(decoded.type == madoka::MessageType::KEEPALIVE);
        assert(decoded.payload.empty());
    }

    {
        std::vector<uint8_t> ipv6_packet(1280);
        for (std::size_t i = 0; i < ipv6_packet.size(); ++i) {
            ipv6_packet[i] = static_cast<uint8_t>(i & 0xFF);
        }
        madoka::Message original{.type = madoka::MessageType::DATA,
                                 .payload = ipv6_packet};
        auto bytes = madoka::message_encode(original);
        assert(bytes.size() == 4 + 1280);
        madoka::Message decoded{};
        bool ok = madoka::message_decode(bytes, &decoded);
        assert(ok);
        assert(decoded == original);
        assert(decoded.payload.size() == 1280);
    }

    {
        std::vector<uint8_t> max_payload(madoka::MAX_PAYLOAD_SIZE, 0x42);
        madoka::Message original{.type = madoka::MessageType::DATA,
                                 .payload = max_payload};
        auto bytes = madoka::message_encode(original);
        assert(bytes.size() == madoka::MAX_MESSAGE_SIZE);
        madoka::Message decoded{};
        bool ok = madoka::message_decode(bytes, &decoded);
        assert(ok);
        assert(decoded == original);
        assert(decoded.payload.size() == madoka::MAX_PAYLOAD_SIZE);
    }

    std::cout << "  -> PASSED: Round-trip preserved identical messages across "
                 "all types.\n";
}

void test_error_handling() {
    std::cout << "[TEST] 3. Testing error detection (invalid version, size, "
                 "and payload limits)...\n";

    for (std::size_t len = 0; len < 4; ++len) {
        std::vector<uint8_t> short_buf(len, 0x01);
        madoka::Message dummy{};
        std::string err;
        bool ok = madoka::message_decode(short_buf, &dummy, &err);
        assert(!ok);
        assert(!err.empty());
    }

    for (uint8_t bad_version :
         {uint8_t{0}, uint8_t{2}, uint8_t{99}, uint8_t{255}}) {
        std::vector<uint8_t> bad_buf = {bad_version, 0x01, 0x00, 0x00};
        madoka::Message dummy{};
        std::string err;
        bool ok = madoka::message_decode(bad_buf, &dummy, &err);
        assert(!ok);
    }

    for (uint8_t bad_type :
         {uint8_t{0}, uint8_t{5}, uint8_t{10}, uint8_t{255}}) {
        std::vector<uint8_t> bad_buf = {0x01, bad_type, 0x00, 0x00};
        madoka::Message dummy{};
        std::string err;
        bool ok = madoka::message_decode(bad_buf, &dummy, &err);
        assert(!ok);
    }

    {
        std::vector<uint8_t> oversized_header = {
            0x01,
            0x01,
            static_cast<uint8_t>((4093 >> 8) & 0xFF),
            static_cast<uint8_t>(4093 & 0xFF)};
        madoka::Message dummy{};
        std::string err;
        assert(!madoka::message_decode(oversized_header, &dummy, &err));

        std::vector<uint8_t> max_u16_header = {0x01, 0x01, 0xFF, 0xFF};
        assert(!madoka::message_decode(max_u16_header, &dummy, &err));
    }

    {
        std::vector<uint8_t> too_large_payload(madoka::MAX_PAYLOAD_SIZE + 1,
                                               0xAA);
        madoka::Message invalid_msg{.type = madoka::MessageType::DATA,
                                    .payload = too_large_payload};

        std::string err;
        assert(!madoka::message_validate(invalid_msg, &err));
        assert(madoka::message_encode(invalid_msg).empty());
    }

    {
        std::vector<uint8_t> short_hdr = {0x01, 0x01};
        assert(madoka::message_peek_size(short_hdr) == std::nullopt);

        std::vector<uint8_t> valid_hdr = {0x01, 0x03, 0x05, 0x00};
        auto size = madoka::message_peek_size(valid_hdr);
        assert(size.has_value() && *size == 1284);

        std::vector<uint8_t> bad_ver = {0x02, 0x01, 0x00, 0x00};
        std::string err;
        assert(!madoka::message_peek_size(bad_ver, &err).has_value());
        assert(!err.empty());
    }

    std::cout << "  -> PASSED: All error conditions rejected safely without "
                 "invalid allocations.\n";
}

int main() {
    try {
        test_hello_encode();
        test_round_trip();
        test_error_handling();
        std::cout << "\nAll protocol unit tests passed successfully!\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Unexpected test failure: " << ex.what() << '\n';
        return 1;
    }
}
