#include "core/app.hpp"
#include "network/data_serialization.hpp"
#include "network/distance_vector.hpp"
#include "network/forwarding.hpp"
#include "network/route_advertisement.hpp"
#include "network/serialization.hpp"
#include "protocol/codec.hpp"

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

madoka::Message control_wire(const madoka::RouteAdvertisement& advertisement) {
    const auto control = madoka::control_message_create(
        madoka::ControlMessageType::ROUTE_ADVERTISEMENT,
        advertisement.sequence_number,
        advertisement.sender,
        madoka::serialize_route_advertisement(advertisement));
    return madoka::Message{.type = madoka::MessageType::Control,
                           .payload =
                               madoka::serialize_control_message(control)};
}

bool send_frame(madoka::AppPeerSession& session,
                const madoka::Message& message,
                std::string* error = nullptr) {
    std::lock_guard<std::mutex> lock(session.send_mutex);
    return madoka::transport_send(&session.transport, message, error);
}

std::shared_ptr<madoka::AppPeerSession> find_session(
    const std::vector<std::shared_ptr<madoka::AppPeerSession>>& sessions,
    const madoka::NodeId& peer_id) {
    for (const auto& session : sessions) {
        if (session->transport.peer_node_id.has_value() &&
            *session->transport.peer_node_id == peer_id) {
            return session;
        }
    }
    return nullptr;
}

std::vector<uint8_t> ipv6_payload(const madoka::IPv6& source,
                                  const madoka::IPv6& destination) {
    std::vector<uint8_t> payload(40, 0);
    payload[0] = 0x60;
    std::copy(source.begin(), source.end(), payload.begin() + 8);
    std::copy(destination.begin(), destination.end(), payload.begin() + 24);
    return payload;
}

void receive_route_advertisement(madoka::AppPeerSession& session,
                                 madoka::RouteAdvertisement* out) {
    madoka::Message wire{};
    std::string error;
    assert(madoka::transport_receive(&session.transport,
                                     &wire,
                                     std::chrono::milliseconds(3000),
                                     nullptr,
                                     &error));
    assert(wire.type == madoka::MessageType::Control);
    madoka::ControlMessage control{};
    assert(madoka::deserialize_control_message(wire.payload, &control, &error));
    assert(control.type == madoka::ControlMessageType::ROUTE_ADVERTISEMENT);
    assert(
        madoka::deserialize_route_advertisement(control.payload, out, &error));
}

} // namespace

int main() {
    std::cout << "=== Madoka A-B-C Multi-hop Integration Test ===\n";
    madoka::Identity a_identity{};
    madoka::Identity b_identity{};
    madoka::Identity c_identity{};
    std::string error;
    assert(madoka::identity_generate(&a_identity, &error));
    assert(madoka::identity_generate(&b_identity, &error));
    assert(madoka::identity_generate(&c_identity, &error));
    const auto a_cfg = tls_config(a_identity);
    const auto b_cfg = tls_config(b_identity);
    const auto c_cfg = tls_config(c_identity);

    madoka::TransportServerState b_server{};
    madoka::TransportServerState c_server{};
    assert(madoka::transport_server_init_tls(
        &b_server, b_cfg, 0, "::1", nullptr, &error));
    assert(madoka::transport_server_init_tls(
        &c_server, c_cfg, 0, "::1", nullptr, &error));
    assert(madoka::transport_server_start(&b_server, &error));
    assert(madoka::transport_server_start(&c_server, &error));

    auto a_to_b = std::make_shared<madoka::AppPeerSession>();
    auto b_from_a = std::make_shared<madoka::AppPeerSession>();
    auto b_to_c = std::make_shared<madoka::AppPeerSession>();
    auto c_from_b = std::make_shared<madoka::AppPeerSession>();

    std::thread connect_a([&] {
        assert(madoka::transport_connect_tls(
            &a_to_b->transport,
            a_cfg,
            "::1",
            madoka::transport_server_local_port(b_server),
            std::nullopt,
            std::chrono::milliseconds(3000),
            &error));
    });
    assert(madoka::transport_accept(&b_server,
                                    &b_from_a->transport,
                                    std::chrono::milliseconds(3000),
                                    &error));
    connect_a.join();

    std::thread connect_b([&] {
        assert(madoka::transport_connect_tls(
            &b_to_c->transport,
            b_cfg,
            "::1",
            madoka::transport_server_local_port(c_server),
            std::nullopt,
            std::chrono::milliseconds(3000),
            &error));
    });
    assert(madoka::transport_accept(&c_server,
                                    &c_from_b->transport,
                                    std::chrono::milliseconds(3000),
                                    &error));
    connect_b.join();

    const madoka::NodeId node_a = *b_from_a->transport.peer_node_id;
    const madoka::NodeId node_b = *c_from_b->transport.peer_node_id;
    const madoka::NodeId node_c = *b_to_c->transport.peer_node_id;
    madoka::IPv6 network{};
    network[0] = 0xfd;
    const auto ip_a = madoka::virtual_address(network, node_a);
    const auto ip_b = madoka::virtual_address(network, node_b);
    const auto ip_c = madoka::virtual_address(network, node_c);

    assert(*a_to_b->transport.peer_node_id == node_b);
    assert(*c_from_b->transport.peer_node_id == node_b);
    assert(*a_to_b->transport.peer_node_id != node_c);
    assert(find_session({a_to_b}, node_c) == nullptr);
    assert(find_session({c_from_b}, node_a) == nullptr);

    madoka::RouteTable routes_c = madoka::routing_init();
    assert(madoka::routing_add_route(
        routes_c, madoka::route_create(ip_c, node_c, 1, 0, node_c)));
    madoka::RouteAdvertisement c_advertisement{.sender = node_c,
                                               .generation = 1,
                                               .sequence_number = 1,
                                               .routes = routes_c.routes};
    assert(send_frame(*c_from_b, control_wire(c_advertisement), &error));
    madoka::RouteAdvertisement received_c{};
    receive_route_advertisement(*b_to_c, &received_c);
    assert(received_c.sender == node_c);

    madoka::RouteTable routes_b = madoka::routing_init();
    assert(madoka::routing_add_route(
        routes_b, madoka::route_create(ip_a, node_a, 1, 0, node_a)));
    assert(madoka::routing_add_route(
        routes_b, madoka::route_create(ip_c, node_c, 1, 0, node_c)));
    madoka::RouteOriginStates b_versions;
    assert(madoka::distance_vector_update(
        routes_b, node_c, received_c, 1, 1, &b_versions));

    madoka::RouteAdvertisement b_advertisement =
        madoka::route_create_advertisement(
            node_b,
            routes_b,
            1,
            node_a,
            madoka::SplitHorizonMode::PoisonReverse,
            1);
    assert(send_frame(*b_from_a, control_wire(b_advertisement), &error));
    madoka::RouteAdvertisement received_b{};
    receive_route_advertisement(*a_to_b, &received_b);

    madoka::RouteTable routes_a = madoka::routing_init();
    assert(madoka::routing_add_route(
        routes_a, madoka::route_create(ip_b, node_b, 1, 0, node_b)));
    madoka::RouteOriginStates a_versions;
    assert(madoka::distance_vector_update(
        routes_a, node_b, received_b, 2, 1, &a_versions));
    const auto* a_to_c = madoka::routing_find_route(routes_a, node_c);
    assert(a_to_c != nullptr);
    assert(a_to_c->destination == ip_c);
    assert(a_to_c->destination_node == node_c);
    assert(a_to_c->next_hop == node_b);
    assert(a_to_c->metric == 2);

    const auto payload_a_to_c = ipv6_payload(ip_a, ip_c);
    madoka::DataPacket packet_a_to_c = madoka::data_packet_create(
        madoka::PacketType::DATA, node_a, node_c, 1, 4, payload_a_to_c);
    assert(send_frame(
        *a_to_b,
        madoka::Message{.type = madoka::MessageType::Data,
                        .payload = madoka::serialize_packet(packet_a_to_c)},
        &error));

    madoka::Message b_wire{};
    assert(madoka::transport_receive(&b_from_a->transport,
                                     &b_wire,
                                     std::chrono::milliseconds(3000),
                                     nullptr,
                                     &error));
    madoka::DataPacket b_packet{};
    assert(madoka::deserialize_packet(b_wire.payload, &b_packet, &error));
    auto b_forwarder = madoka::forwarding_init(&routes_b, &node_b);
    madoka::forwarding_set_transmit_handler(
        &b_forwarder,
        [&](const madoka::NodeId& next_hop, const madoka::DataPacket& packet) {
            if (packet.destination == node_c) {
                assert(next_hop == node_c);
                assert(
                    send_frame(*b_to_c,
                               madoka::Message{
                                   .type = madoka::MessageType::Data,
                                   .payload = madoka::serialize_packet(packet)},
                               &error));
            } else {
                assert(packet.destination == node_a);
                assert(next_hop == node_a);
                assert(
                    send_frame(*b_from_a,
                               madoka::Message{
                                   .type = madoka::MessageType::Data,
                                   .payload = madoka::serialize_packet(packet)},
                               &error));
            }
        });
    madoka::forwarding_forward(&b_forwarder, &b_packet);
    assert(b_packet.ttl == 3);

    madoka::Message c_wire{};
    assert(madoka::transport_receive(&c_from_b->transport,
                                     &c_wire,
                                     std::chrono::milliseconds(3000),
                                     nullptr,
                                     &error));
    madoka::DataPacket c_packet{};
    assert(madoka::deserialize_packet(c_wire.payload, &c_packet, &error));
    bool c_delivered = false;
    auto c_forwarder = madoka::forwarding_init(&routes_c, &node_c);
    madoka::forwarding_set_local_delivery_handler(
        &c_forwarder, [&](const madoka::DataPacket& packet) {
            c_delivered = packet.payload == payload_a_to_c;
        });
    madoka::forwarding_forward(&c_forwarder, &c_packet);
    assert(c_delivered);

    const auto payload_c_to_a = ipv6_payload(ip_c, ip_a);
    madoka::DataPacket packet_c_to_a = madoka::data_packet_create(
        madoka::PacketType::DATA, node_c, node_a, 2, 4, payload_c_to_a);
    assert(send_frame(
        *c_from_b,
        madoka::Message{.type = madoka::MessageType::Data,
                        .payload = madoka::serialize_packet(packet_c_to_a)},
        &error));
    madoka::Message b_return_wire{};
    assert(madoka::transport_receive(&b_to_c->transport,
                                     &b_return_wire,
                                     std::chrono::milliseconds(3000),
                                     nullptr,
                                     &error));
    madoka::DataPacket b_return{};
    assert(
        madoka::deserialize_packet(b_return_wire.payload, &b_return, &error));
    madoka::forwarding_forward(&b_forwarder, &b_return);
    assert(b_return.ttl == 3);

    madoka::Message a_wire{};
    assert(madoka::transport_receive(&a_to_b->transport,
                                     &a_wire,
                                     std::chrono::milliseconds(3000),
                                     nullptr,
                                     &error));
    madoka::DataPacket a_packet{};
    assert(madoka::deserialize_packet(a_wire.payload, &a_packet, &error));
    bool a_delivered = false;
    auto a_forwarder = madoka::forwarding_init(&routes_a, &node_a);
    madoka::forwarding_set_local_delivery_handler(
        &a_forwarder, [&](const madoka::DataPacket& packet) {
            a_delivered = packet.payload == payload_c_to_a;
        });
    madoka::forwarding_forward(&a_forwarder, &a_packet);
    assert(a_delivered);

    madoka::transport_close(&a_to_b->transport);
    madoka::transport_close(&b_from_a->transport);
    madoka::transport_close(&b_to_c->transport);
    madoka::transport_close(&c_from_b->transport);
    madoka::transport_server_close(&b_server);
    madoka::transport_server_close(&c_server);
    madoka::identity_close(&c_identity);
    madoka::identity_close(&b_identity);
    madoka::identity_close(&a_identity);
    std::cout << "A-B-C forwarding, return path, TTL decrement and no A-C "
                 "session passed.\n";
    return 0;
}
