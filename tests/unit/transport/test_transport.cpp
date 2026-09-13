#include "protocol/codec.hpp"
#include "transport/session.hpp"

#include <cassert>
#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

void test_basic_handshake() {
    std::cout << "[TEST] 1. Testing basic TCP connection and Hello/KeepAlive "
                 "handshake...\n";

    madoka::TransportServerState server{};
    assert(madoka::transport_server_init(&server, 0, "::1"));
    assert(madoka::transport_server_start(&server));
    const uint16_t server_port = madoka::transport_server_local_port(server);
    assert(server_port > 0);

    std::thread client_thread([server_port]() {
        madoka::TransportSessionState client{};
        assert(madoka::transport_connect(&client, "::1", server_port));
        assert(madoka::transport_is_open(client));

        madoka::Message hello_msg{.type = madoka::MessageType::Hello,
                                  .payload = {0x01, 0x02, 0x03, 0x04}};
        assert(madoka::transport_send(&client, hello_msg));

        madoka::Message reply{};
        assert(madoka::transport_receive(
            &client, &reply, std::chrono::milliseconds(2000)));
        assert(reply.type == madoka::MessageType::KeepAlive);
        assert(reply.payload.empty());

        madoka::transport_close(&client);
    });

    madoka::TransportSessionState server_session{};
    assert(madoka::transport_accept(
        &server, &server_session, std::chrono::milliseconds(2000)));
    assert(madoka::transport_is_open(server_session));

    madoka::Message received{};
    assert(madoka::transport_receive(
        &server_session, &received, std::chrono::milliseconds(2000)));
    assert(received.type == madoka::MessageType::Hello);
    assert(received.payload == std::vector<uint8_t>({0x01, 0x02, 0x03, 0x04}));

    madoka::Message reply_msg{.type = madoka::MessageType::KeepAlive};
    assert(madoka::transport_send(&server_session, reply_msg));

    client_thread.join();
    madoka::transport_close(&server_session);
    madoka::transport_server_close(&server);
    std::cout << "  -> PASSED: Basic connection and handshake completed "
                 "successfully.\n";
}

void test_fragmented_delivery() {
    std::cout << "[TEST] 2. Testing fragmented delivery (including fragmented "
                 "header and payload)...\n";

    madoka::TransportServerState server{};
    assert(madoka::transport_server_init(&server, 0, "::1"));
    assert(madoka::transport_server_start(&server));
    const uint16_t server_port = madoka::transport_server_local_port(server);

    std::thread client_thread([server_port]() {
        madoka::TransportSessionState client{};
        assert(madoka::transport_connect(&client, "::1", server_port));

        const std::vector<uint8_t> wire_bytes = {
            0x01, 0x01, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD};

        ::send(client.socket.fd,
               reinterpret_cast<const char*>(wire_bytes.data()),
               1,
               0);
        std::this_thread::sleep_for(std::chrono::milliseconds(25));

        ::send(client.socket.fd,
               reinterpret_cast<const char*>(wire_bytes.data() + 1),
               2,
               0);
        std::this_thread::sleep_for(std::chrono::milliseconds(25));

        ::send(client.socket.fd,
               reinterpret_cast<const char*>(wire_bytes.data() + 3),
               1,
               0);
        std::this_thread::sleep_for(std::chrono::milliseconds(25));

        ::send(client.socket.fd,
               reinterpret_cast<const char*>(wire_bytes.data() + 4),
               2,
               0);
        std::this_thread::sleep_for(std::chrono::milliseconds(25));

        ::send(client.socket.fd,
               reinterpret_cast<const char*>(wire_bytes.data() + 6),
               2,
               0);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        madoka::transport_close(&client);
    });

    madoka::TransportSessionState server_session{};
    assert(madoka::transport_accept(
        &server, &server_session, std::chrono::milliseconds(2000)));

    madoka::Message received{};
    assert(madoka::transport_receive(
        &server_session, &received, std::chrono::milliseconds(2000)));
    assert(received.type == madoka::MessageType::Hello);
    assert(received.payload == std::vector<uint8_t>({0xAA, 0xBB, 0xCC, 0xDD}));

    client_thread.join();
    madoka::transport_close(&server_session);
    madoka::transport_server_close(&server);
    std::cout << "  -> PASSED: Fragmented header and payload reassembled "
                 "seamlessly.\n";
}

void test_multiple_messages_in_stream() {
    std::cout << "[TEST] 3. Testing multiple messages concatenated in a single "
                 "TCP stream...\n";

    madoka::TransportServerState server{};
    assert(madoka::transport_server_init(&server, 0, "::1"));
    assert(madoka::transport_server_start(&server));
    const uint16_t server_port = madoka::transport_server_local_port(server);

    std::thread client_thread([server_port]() {
        madoka::TransportSessionState client{};
        assert(madoka::transport_connect(&client, "::1", server_port));

        madoka::Message msg1{.type = madoka::MessageType::Hello,
                             .payload = {0x01, 0x02}};
        std::vector<uint8_t> data_payload(1280, 0x55);
        madoka::Message msg2{.type = madoka::MessageType::Data,
                             .payload = data_payload};
        madoka::Message msg3{.type = madoka::MessageType::KeepAlive};

        std::vector<uint8_t> batch;
        auto b1 = madoka::message_encode(msg1);
        auto b2 = madoka::message_encode(msg2);
        auto b3 = madoka::message_encode(msg3);
        batch.insert(batch.end(), b1.begin(), b1.end());
        batch.insert(batch.end(), b2.begin(), b2.end());
        batch.insert(batch.end(), b3.begin(), b3.end());

        ::send(client.socket.fd,
               reinterpret_cast<const char*>(batch.data()),
               static_cast<int>(batch.size()),
               0);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        madoka::transport_close(&client);
    });

    madoka::TransportSessionState server_session{};
    assert(madoka::transport_accept(
        &server, &server_session, std::chrono::milliseconds(2000)));

    madoka::Message r1{};
    assert(madoka::transport_receive(
        &server_session, &r1, std::chrono::milliseconds(2000)));
    assert(r1.type == madoka::MessageType::Hello);
    assert(r1.payload == std::vector<uint8_t>({0x01, 0x02}));

    madoka::Message r2{};
    assert(madoka::transport_receive(
        &server_session, &r2, std::chrono::milliseconds(2000)));
    assert(r2.type == madoka::MessageType::Data);
    assert(r2.payload.size() == 1280);
    assert(r2.payload[0] == 0x55 && r2.payload[1279] == 0x55);

    madoka::Message r3{};
    assert(madoka::transport_receive(
        &server_session, &r3, std::chrono::milliseconds(2000)));
    assert(r3.type == madoka::MessageType::KeepAlive);
    assert(r3.payload.empty());

    client_thread.join();
    madoka::transport_close(&server_session);
    madoka::transport_server_close(&server);
    std::cout << "  -> PASSED: Multiple batched messages read and delimited "
                 "accurately.\n";
}

void test_so_rcvtimeo_timeout() {
    std::cout << "[TEST] 4. Testing SO_RCVTIMEO timeout without polling...\n";

    madoka::TransportServerState server{};
    assert(madoka::transport_server_init(&server, 0, "::1"));
    assert(madoka::transport_server_start(&server));
    const uint16_t server_port = madoka::transport_server_local_port(server);

    std::thread client_thread([server_port]() {
        madoka::TransportSessionState client{};
        assert(madoka::transport_connect(&client, "::1", server_port));
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        madoka::transport_close(&client);
    });

    madoka::TransportSessionState server_session{};
    assert(madoka::transport_accept(
        &server, &server_session, std::chrono::milliseconds(2000)));

    const auto start = std::chrono::steady_clock::now();
    madoka::Message dummy{};
    std::string err;
    bool ok = madoka::transport_receive(
        &server_session, &dummy, std::chrono::milliseconds(100), nullptr, &err);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::steady_clock::now() - start)
                             .count();

    assert(!ok);
    assert(elapsed >= 80);
    assert(madoka::transport_is_open(server_session));
    std::cout << "  -> PASSED: SO_RCVTIMEO timed out correctly (" << elapsed
              << "ms).\n";

    client_thread.join();
    madoka::transport_close(&server_session);
    madoka::transport_server_close(&server);
}

void test_error_handling_and_buffer_limits() {
    std::cout << "[TEST] 5. Testing error handling, invalid header, and "
                 "oversized message rejection...\n";

    madoka::TransportServerState server{};
    assert(madoka::transport_server_init(&server, 0, "::1"));
    assert(madoka::transport_server_start(&server));
    const uint16_t server_port = madoka::transport_server_local_port(server);

    {
        std::thread client_thread([server_port]() {
            madoka::TransportSessionState client{};
            assert(madoka::transport_connect(&client, "::1", server_port));
            const std::vector<uint8_t> bad_header = {0x99, 0x01, 0x00, 0x00};
            ::send(client.socket.fd,
                   reinterpret_cast<const char*>(bad_header.data()),
                   4,
                   0);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            madoka::transport_close(&client);
        });

        madoka::TransportSessionState server_session{};
        assert(madoka::transport_accept(
            &server, &server_session, std::chrono::milliseconds(2000)));
        madoka::Message dummy{};
        bool ok = madoka::transport_receive(
            &server_session, &dummy, std::chrono::milliseconds(2000));
        assert(!ok);
        assert(!madoka::transport_is_open(server_session));

        client_thread.join();
    }

    {
        std::thread client_thread([server_port]() {
            madoka::TransportSessionState client{};
            assert(madoka::transport_connect(&client, "::1", server_port));
            const uint16_t too_large = 4093;
            const std::vector<uint8_t> oversized_header = {
                0x01,
                0x01,
                static_cast<uint8_t>((too_large >> 8) & 0xFF),
                static_cast<uint8_t>(too_large & 0xFF)};
            ::send(client.socket.fd,
                   reinterpret_cast<const char*>(oversized_header.data()),
                   4,
                   0);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            madoka::transport_close(&client);
        });

        madoka::TransportSessionState server_session{};
        assert(madoka::transport_accept(
            &server, &server_session, std::chrono::milliseconds(2000)));
        madoka::Message dummy{};
        bool ok = madoka::transport_receive(
            &server_session, &dummy, std::chrono::milliseconds(2000));
        assert(!ok);
        assert(!madoka::transport_is_open(server_session));

        client_thread.join();
    }

    madoka::transport_server_close(&server);
    std::cout << "  -> PASSED: Invalid and oversized messages correctly "
                 "rejected and session closed.\n";
}

int main() {
    try {
        test_basic_handshake();
        test_fragmented_delivery();
        test_multiple_messages_in_stream();
        test_so_rcvtimeo_timeout();
        test_error_handling_and_buffer_limits();
        std::cout
            << "\nAll transport unit/integration tests passed successfully!\n";
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Unexpected test failure: " << ex.what() << '\n';
        return 1;
    }
}
