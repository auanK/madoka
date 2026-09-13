#include "crypto/identity.hpp"
#include "protocol/message.hpp"
#include "transport/session.hpp"

#include <cassert>
#include <chrono>
#include <iostream>
#include <thread>

namespace {

madoka::TlsConfig tls_config(const madoka::Identity& identity) {
    return madoka::TlsConfig{.identity_key = identity.key,
                             .identity_id = identity.id,
                             .generation = identity.generation};
}

void test_in_memory_certificate_matches_identity() {
    madoka::Identity identity{};
    std::string error;
    assert(madoka::identity_generate(&identity, &error));

    madoka::TlsContext context{};
    assert(madoka::tls_context_init(
        &context, madoka::TlsRole::Server, tls_config(identity), &error));
    assert(madoka::tls_context_matches_identity(context, identity.id, &error));

    madoka::NodeId wrong = identity.id;
    wrong[0] ^= 1;
    assert(!madoka::tls_context_matches_identity(context, wrong, &error));

    madoka::tls_context_destroy(&context);
    madoka::identity_close(&identity);
}

void test_mutual_tls_and_encrypted_message() {
    using namespace std::chrono_literals;
    madoka::Identity server_identity{};
    madoka::Identity client_identity{};
    std::string error;
    assert(madoka::identity_generate(&server_identity, &error));
    assert(madoka::identity_generate(&client_identity, &error));

    madoka::TransportServerState server{};
    assert(madoka::transport_server_init_tls(
        &server, tls_config(server_identity), 0, "127.0.0.1", nullptr, &error));
    assert(madoka::transport_server_start(&server, &error));
    const uint16_t port = madoka::transport_server_local_port(server);

    std::thread worker([&] {
        std::string server_error;
        madoka::TransportSessionState accepted{};
        assert(madoka::transport_accept(&server, &accepted, 5s, &server_error));
        assert(accepted.peer_node_id == client_identity.id);

        madoka::Message request{};
        assert(madoka::transport_receive(
            &accepted, &request, 5s, nullptr, &server_error));
        assert(request.type == madoka::MessageType::Control);
        assert(request.payload == std::vector<uint8_t>({1, 2, 3}));
        assert(madoka::transport_send(
            &accepted,
            madoka::Message{.type = madoka::MessageType::Control,
                            .payload = {4, 5, 6}},
            &server_error));
        madoka::transport_close(&accepted);
    });

    madoka::TransportSessionState client{};
    assert(madoka::transport_connect_tls(&client,
                                         tls_config(client_identity),
                                         "127.0.0.1",
                                         port,
                                         server_identity.id,
                                         5s,
                                         &error));
    assert(client.peer_node_id == server_identity.id);
    assert(madoka::transport_send(
        &client,
        madoka::Message{.type = madoka::MessageType::Control,
                        .payload = {1, 2, 3}},
        &error));
    madoka::Message response{};
    assert(madoka::transport_receive(&client, &response, 5s, nullptr, &error));
    assert(response.payload == std::vector<uint8_t>({4, 5, 6}));

    madoka::transport_close(&client);
    worker.join();
    madoka::transport_server_close(&server);
    madoka::identity_close(&client_identity);
    madoka::identity_close(&server_identity);
}

void test_expected_node_id_is_enforced() {
    using namespace std::chrono_literals;
    madoka::Identity server_identity{};
    madoka::Identity client_identity{};
    madoka::Identity other_identity{};
    std::string error;
    assert(madoka::identity_generate(&server_identity, &error));
    assert(madoka::identity_generate(&client_identity, &error));
    assert(madoka::identity_generate(&other_identity, &error));

    madoka::TransportServerState server{};
    assert(madoka::transport_server_init_tls(
        &server, tls_config(server_identity), 0, "127.0.0.1", nullptr, &error));
    assert(madoka::transport_server_start(&server, &error));

    std::thread worker([&] {
        std::string server_error;
        madoka::TransportSessionState accepted{};
        if (madoka::transport_accept(&server, &accepted, 5s, &server_error)) {
            madoka::transport_close(&accepted);
        }
    });

    madoka::TransportSessionState client{};
    assert(!madoka::transport_connect_tls(
        &client,
        tls_config(client_identity),
        "127.0.0.1",
        madoka::transport_server_local_port(server),
        other_identity.id,
        5s,
        &error));

    worker.join();
    madoka::transport_server_close(&server);
    madoka::identity_close(&other_identity);
    madoka::identity_close(&client_identity);
    madoka::identity_close(&server_identity);
}

} // namespace

int main() {
    test_in_memory_certificate_matches_identity();
    test_mutual_tls_and_encrypted_message();
    test_expected_node_id_is_enforced();
    std::cout << "In-memory Ed25519 TLS tests passed.\n";
    return 0;
}
