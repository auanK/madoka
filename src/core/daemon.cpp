#include "core/daemon.hpp"

#include "core/app.hpp"
#include "core/lifecycle.hpp"
#include "network/control_message.hpp"
#include "network/data_serialization.hpp"
#include "network/distance_vector.hpp"
#include "network/forwarding.hpp"
#include "network/heartbeat.hpp"
#include "network/join.hpp"
#include "network/serialization.hpp"
#include "platform/private_storage.hpp"
#include "protocol/codec.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <memory>
#include <openssl/evp.h>
#include <thread>
#include <utility>

namespace madoka {

namespace {

constexpr std::size_t MAX_PEER_SESSIONS = 16;
constexpr std::size_t MAX_MESSAGES_PER_SECOND = 1000;

uint64_t now_ms() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

uint64_t steady_now_ms() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count());
}

bool extract_public_key(const Identity& identity,
                        std::array<uint8_t, 32>& public_key) {
    std::size_t size = public_key.size();
    return identity.key != nullptr &&
           EVP_PKEY_get_raw_public_key(static_cast<EVP_PKEY*>(identity.key),
                                       public_key.data(),
                                       &size) == 1 &&
           size == public_key.size();
}

bool valid_node_contact(const Config& config, const NodeContact& contact) {
    NodeId derived{};
    std::size_t size = derived.size();
    std::string host;
    uint16_t port = 0;
    return contact.id != NodeId{} &&
           EVP_Q_digest(nullptr,
                        "SHA256",
                        nullptr,
                        contact.public_key.data(),
                        contact.public_key.size(),
                        derived.data(),
                        &size) == 1 &&
           size == derived.size() && derived == contact.id &&
           contact.virtual_address ==
               virtual_address(config.network, contact.id) &&
           parse_endpoint(contact.endpoint, &host, &port) && port != 0;
}

bool peer_is_trusted(AppState& app, const NodeId& peer_id) {
    std::lock_guard<std::mutex> lock(app.trust_mutex);
    return trust_contains(app.trust, peer_id);
}

TlsConfig tls_config_for(const AppState& app) {
    return TlsConfig{.identity_key = app.identity.key,
                     .identity_id = app.identity.id,
                     .generation = app.identity.generation};
}

void update_status_file(AppState& app);

Message make_control_wire(const ControlMessage& control) {
    return Message{.type = MessageType::Control,
                   .payload = serialize_control_message(control)};
}

bool send_on_session(const std::shared_ptr<AppPeerSession>& session,
                     const Message& message,
                     std::string* error = nullptr) {
    if (!session) {
        if (error)
            *error = "Peer session is null";
        return false;
    }
    std::lock_guard<std::mutex> lock(session->send_mutex);
    return transport_send(&session->transport, message, error);
}

void close_session(const std::shared_ptr<AppPeerSession>& session) {
    if (!session)
        return;
    std::scoped_lock lock(session->send_mutex, session->receive_mutex);
    transport_close(&session->transport);
}

bool session_is_open(const std::shared_ptr<AppPeerSession>& session) {
    if (!session)
        return false;
    return transport_is_open(session->transport);
}

bool receive_on_session(const std::shared_ptr<AppPeerSession>& session,
                        Message* message,
                        std::chrono::milliseconds timeout,
                        bool* closed,
                        std::string* error) {
    if (!session)
        return false;
    std::lock_guard<std::mutex> lock(session->receive_mutex);
    return transport_receive(
        &session->transport, message, timeout, closed, error);
}

bool send_control(const std::shared_ptr<AppPeerSession>& session,
                  ControlMessageType type,
                  uint64_t sequence,
                  const NodeId& sender,
                  std::vector<uint8_t> payload,
                  std::string* error = nullptr) {
    const auto control =
        control_message_create(type, sequence, sender, std::move(payload));
    return send_on_session(session, make_control_wire(control), error);
}

bool receive_control(const std::shared_ptr<AppPeerSession>& session,
                     ControlMessage* control,
                     std::chrono::milliseconds timeout,
                     std::string* error = nullptr) {
    Message wire{};
    if (!receive_on_session(session, &wire, timeout, nullptr, error) ||
        wire.type != MessageType::Control) {
        return false;
    }
    return deserialize_control_message(wire.payload, control, error);
}

std::shared_ptr<AppPeerSession> find_idle_session(AppState& app,
                                                  const NodeId& peer_id) {
    std::lock_guard<std::mutex> lock(app.sessions_mutex);
    for (const auto& session : app.sessions) {
        if (session->peer_id.has_value() && *session->peer_id == peer_id &&
            !session->worker_started) {
            return session;
        }
    }
    return nullptr;
}

void rebuild_routing_table(AppState& app);
bool activate_neighbor(AppState& app, const NodeContact& contact);
void deactivate_neighbor(AppState& app, const NodeId& peer_id);
void touch_neighbor(AppState& app, const NodeId& peer_id);

void remove_session(AppState& app,
                    const std::shared_ptr<AppPeerSession>& session) {
    std::optional<NodeId> peer_id;
    bool removed = false;
    {
        std::lock_guard<std::mutex> lock(app.sessions_mutex);
        const auto it =
            std::find(app.sessions.begin(), app.sessions.end(), session);
        if (it != app.sessions.end()) {
            peer_id = (*it)->peer_id;
            app.sessions.erase(it);
            removed = true;
        }
    }
    if (removed && peer_id.has_value()) {
        deactivate_neighbor(app, *peer_id);
    }
}

bool register_session(AppState& app,
                      const std::shared_ptr<AppPeerSession>& session) {
    if (!session || !session->peer_id.has_value()) {
        return false;
    }
    std::lock_guard<std::mutex> lock(app.sessions_mutex);
    if (app.sessions.size() >= MAX_PEER_SESSIONS) {
        return false;
    }
    const auto duplicate = std::find_if(
        app.sessions.begin(), app.sessions.end(), [&](const auto& existing) {
            return existing->peer_id.has_value() &&
                   *existing->peer_id == *session->peer_id &&
                   session_is_open(existing);
        });
    if (duplicate != app.sessions.end()) {
        return false;
    }
    app.sessions.push_back(session);
    return true;
}

bool bind_session(AppState& app,
                  const std::shared_ptr<AppPeerSession>& session,
                  const NodeContact& contact) {
    {
        std::lock_guard<std::mutex> lock(app.sessions_mutex);
        if (session->transport.is_tls &&
            (!session->transport.peer_node_id.has_value() ||
             *session->transport.peer_node_id != contact.id)) {
            return false;
        }
        for (const auto& other : app.sessions) {
            if (other != session && other->peer_id.has_value() &&
                *other->peer_id == contact.id) {
                return false;
            }
        }
        session->contact = contact;
    }
    return activate_neighbor(app, contact);
}

std::shared_ptr<AppPeerSession>
find_session_by_next_hop(AppState& app, const NodeId& next_hop) {
    std::vector<std::shared_ptr<AppPeerSession>> sessions;
    {
        std::lock_guard<std::mutex> lock(app.sessions_mutex);
        sessions = app.sessions;
    }
    for (const auto& session : sessions) {
        if (!session->peer_id.has_value() || *session->peer_id != next_hop) {
            continue;
        }
        bool open = false;
        {
            std::lock_guard<std::mutex> send_lock(session->send_mutex);
            open = transport_is_open(session->transport);
        }
        bool active = false;
        {
            std::lock_guard<std::mutex> topology_lock(app.topology_mutex);
            if (const auto* peer = topology_find_peer(app.topology, next_hop)) {
                active = peer_is_alive(*peer, steady_now_ms(), 5000);
            }
        }
        if (open && active) {
            return session;
        }
    }
    return nullptr;
}

std::optional<NodeId> resolve_node_by_virtual_address(AppState& app,
                                                      const IPv6& address) {
    {
        std::lock_guard<std::mutex> lock(app.topology_mutex);
        if (const auto* peer =
                topology_find_by_address(app.topology, address)) {
            return peer->id;
        }
    }
    {
        std::lock_guard<std::mutex> lock(app.kademlia_mutex);
        for (const auto& bucket : app.kademlia_table.buckets) {
            for (const auto& contact : bucket.contacts) {
                if (contact.virtual_address == address &&
                    virtual_address(app.config.network, contact.id) ==
                        address) {
                    return contact.id;
                }
            }
        }
    }
    {
        std::lock_guard<std::mutex> route_lock(app.routing_mutex);
        if (const auto* route =
                routing_find_route(app.routing_table, address)) {
            if (route->destination_node != NodeId{} &&
                virtual_address(app.config.network, route->destination_node) ==
                    address) {
                return route->destination_node;
            }
        }
    }
    return std::nullopt;
}

void run_session(AppState* app, std::shared_ptr<AppPeerSession> session);

void start_session_worker(AppState& app,
                          const std::shared_ptr<AppPeerSession>& session);

void mark_routing_dirty(AppState& app) {
    {
        std::lock_guard<std::mutex> lock(app.routing_wakeup_mutex);
        app.routing_dirty = true;
    }
    app.routing_wakeup.notify_one();
}

void rebuild_routing_table(AppState& app) {
    std::vector<Peer> peers;
    {
        std::lock_guard<std::mutex> lock(app.topology_mutex);
        peers = app.topology.peers;
    }

    std::lock_guard<std::mutex> lock(app.routing_mutex);
    const auto before = app.routing_table.routes;
    routing_clear(app.routing_table);
    const uint64_t timestamp = steady_now_ms();
    for (const auto& peer : peers) {
        if (peer.state != PeerState::Connected ||
            !peer_is_alive(peer, timestamp, 5000)) {
            continue;
        }
        routing_add_route(
            app.routing_table,
            route_create(peer.virtual_address, peer.id, 1, timestamp, peer.id));
    }

    std::vector<NodeId> neighbors;
    neighbors.reserve(app.route_advertisements.size());
    for (const auto& [neighbor, stored] : app.route_advertisements) {
        (void)stored;
        const auto peer = std::find_if(
            peers.begin(), peers.end(), [&](const Peer& candidate) {
                return candidate.id == neighbor &&
                       candidate.state == PeerState::Connected;
            });
        if (peer != peers.end()) {
            neighbors.push_back(neighbor);
        }
    }
    std::sort(neighbors.begin(), neighbors.end());
    for (const auto& neighbor : neighbors) {
        const auto it = app.route_advertisements.find(neighbor);
        if (it != app.route_advertisements.end()) {
            distance_vector_update(app.routing_table,
                                   neighbor,
                                   it->second.advertisement,
                                   timestamp,
                                   1,
                                   static_cast<RouteOriginStates*>(nullptr));
        }
    }

    std::size_t installed = 0;
    std::size_t updated = 0;
    for (const auto& route : app.routing_table.routes) {
        const auto old = std::find_if(
            before.begin(), before.end(), [&](const Route& candidate) {
                return candidate.destination_node == route.destination_node &&
                       candidate.destination == route.destination;
            });
        if (old == before.end()) {
            ++installed;
        } else if (old->next_hop != route.next_hop ||
                   old->metric != route.metric) {
            ++updated;
        }
    }
    app.routing_metrics.routes_installed.fetch_add(installed);
    app.routing_metrics.routes_updated.fetch_add(updated);
}

bool activate_neighbor(AppState& app, const NodeContact& contact) {
    if (contact.id == NodeId{} || contact.id == app.identity.id ||
        !peer_is_trusted(app, contact.id) ||
        contact.virtual_address !=
            virtual_address(app.config.network, contact.id)) {
        return false;
    }
    const uint64_t timestamp = steady_now_ms();
    bool became_connected = false;
    {
        std::lock_guard<std::mutex> lock(app.topology_mutex);
        Peer* peer = topology_find_peer(&app.topology, contact.id);
        if (!peer) {
            peer = nullptr;
            const Peer created = peer_create(contact.id,
                                             contact.virtual_address,
                                             contact.endpoint,
                                             PeerState::Connected,
                                             timestamp);
            if (!topology_add_peer(&app.topology, created)) {
                return false;
            }
            became_connected = true;
        } else {
            became_connected = peer->state != PeerState::Connected;
            peer->virtual_address = contact.virtual_address;
            peer->endpoint = contact.endpoint;
            peer->state = PeerState::Connected;
            peer->last_seen = timestamp;
        }
    }
    if (became_connected) {
        app.routing_metrics.neighbor_up.fetch_add(1);
    }
    rebuild_routing_table(app);
    mark_routing_dirty(app);
    update_status_file(app);
    return true;
}

void deactivate_neighbor(AppState& app, const NodeId& peer_id) {
    bool another_session = false;
    {
        std::lock_guard<std::mutex> lock(app.sessions_mutex);
        another_session = std::any_of(
            app.sessions.begin(), app.sessions.end(), [&](const auto& session) {
                return session->peer_id.has_value() &&
                       *session->peer_id == peer_id;
            });
    }
    if (another_session) {
        return;
    }

    bool was_connected = false;
    {
        std::lock_guard<std::mutex> lock(app.topology_mutex);
        if (auto* peer = topology_find_peer(&app.topology, peer_id)) {
            was_connected = peer->state == PeerState::Connected;
            peer->state = PeerState::Disconnected;
        }
    }
    {
        std::lock_guard<std::mutex> lock(app.routing_mutex);
        app.route_advertisements.erase(peer_id);
    }
    if (was_connected) {
        app.routing_metrics.neighbor_down.fetch_add(1);
    }
    rebuild_routing_table(app);
    mark_routing_dirty(app);
    update_status_file(app);
}

void touch_neighbor(AppState& app, const NodeId& peer_id) {
    bool became_connected = false;
    {
        std::lock_guard<std::mutex> lock(app.topology_mutex);
        if (auto* peer = topology_find_peer(&app.topology, peer_id)) {
            became_connected = peer->state != PeerState::Connected;
            peer->state = PeerState::Connected;
            peer->last_seen = steady_now_ms();
        }
    }
    if (became_connected) {
        app.routing_metrics.neighbor_up.fetch_add(1);
        rebuild_routing_table(app);
        mark_routing_dirty(app);
    }
}

std::vector<std::shared_ptr<AppPeerSession>> active_sessions(AppState& app) {
    std::vector<std::shared_ptr<AppPeerSession>> result;
    {
        std::lock_guard<std::mutex> lock(app.sessions_mutex);
        result = app.sessions;
    }
    const uint64_t now = steady_now_ms();
    result.erase(std::remove_if(result.begin(),
                                result.end(),
                                [&](const auto& session) {
                                    if (!session->peer_id.has_value() ||
                                        !session_is_open(session)) {
                                        return true;
                                    }
                                    std::lock_guard<std::mutex> lock(
                                        app.topology_mutex);
                                    const auto* peer = topology_find_peer(
                                        app.topology, *session->peer_id);
                                    return peer == nullptr ||
                                           !peer_is_alive(*peer, now, 5000);
                                }),
                 result.end());
    return result;
}

void start_session_worker(AppState& app,
                          const std::shared_ptr<AppPeerSession>& session) {
    std::vector<std::thread> completed;
    {
        std::lock_guard<std::mutex> lock(app.sessions_mutex);
        auto worker = app.session_workers.begin();
        while (worker != app.session_workers.end()) {
            if (worker->finished->load(std::memory_order_acquire)) {
                completed.push_back(std::move(worker->thread));
                worker = app.session_workers.erase(worker);
            } else {
                ++worker;
            }
        }
    }
    for (auto& worker : completed) {
        worker.join();
    }

    std::lock_guard<std::mutex> lock(app.sessions_mutex);
    if (session->worker_started) {
        return;
    }
    session->worker_started = true;
    auto finished = std::make_shared<std::atomic_bool>(false);
    app.session_workers.push_back(AppSessionWorker{
        .thread = std::thread([app_ptr = &app, session, finished] {
            run_session(app_ptr, session);
            finished->store(true, std::memory_order_release);
        }),
        .finished = std::move(finished),
    });
}

void accept_loop(AppState* app) {
    while (app->running.load(std::memory_order_relaxed) &&
           !core::lifecycle_is_stop_requested()) {
        auto session = std::make_shared<AppPeerSession>();
        std::string error;
        if (!transport_accept(&app->transport_server,
                              &session->transport,
                              std::chrono::milliseconds{200},
                              &error)) {
            continue;
        }

        if (!app->running.load(std::memory_order_relaxed)) {
            close_session(session);
            break;
        }

        if (!session->transport.peer_node_id.has_value()) {
            close_session(session);
            continue;
        }
        const NodeId peer_id = *session->transport.peer_node_id;
        session->peer_id = peer_id;
        const NodeContact peer_contact{
            .id = peer_id,
            .public_key = session->transport.tls.peer_pubkey,
            .virtual_address = virtual_address(app->config.network, peer_id),
            .endpoint = session->transport.remote_endpoint,
            .last_seen_ms = now_ms(),
        };
        session->contact = peer_contact;
        if (!register_session(*app, session)) {
            close_session(session);
            continue;
        }
        start_session_worker(*app, session);
    }
}

void start_accept_worker(AppState& app) {
    if (!app.accept_worker.joinable()) {
        app.accept_worker = std::thread(accept_loop, &app);
    }
}

bool start_runtime(AppState& app, std::string* error) {
    if (app.config.mtu > MAX_PAYLOAD_SIZE - DATA_PACKET_HEADER_SIZE) {
        if (error) {
            *error = "MTU is too large for a framed Data message";
        }
        return false;
    }

    const TlsConfig tls_config = tls_config_for(app);
    if (!transport_server_init_tls(&app.transport_server,
                                   tls_config,
                                   app.config.listen_port,
                                   app.config.listen_address,
                                   nullptr,
                                   error)) {
        return false;
    }
    if (!tls_context_matches_identity(
            app.transport_server.tls_ctx, app.identity.id, error)) {
        transport_server_close(&app.transport_server);
        return false;
    }
    if (!identity_bump_generation(&app.identity, error)) {
        transport_server_close(&app.transport_server);
        return false;
    }
    if (!vnet_init(&app.vnet, app.config, app.identity, error)) {
        transport_server_close(&app.transport_server);
        return false;
    }
    if (!transport_server_start(&app.transport_server, error)) {
        transport_server_close(&app.transport_server);
        vnet_shutdown(&app.vnet);
        return false;
    }

    std::array<uint8_t, 32> public_key{};
    if (!extract_public_key(app.identity, public_key)) {
        if (error) {
            *error = "Failed to export Ed25519 public key.";
        }
        transport_server_close(&app.transport_server);
        vnet_shutdown(&app.vnet);
        return false;
    }

    app.local_contact = NodeContact{
        .id = app.identity.id,
        .public_key = public_key,
        .virtual_address = app.vnet.address,
        .endpoint =
            format_endpoint(app.config.listen_address,
                            transport_server_local_port(app.transport_server)),
        .last_seen_ms = now_ms(),
    };
    return true;
}

bool validate_ipv6_packet(AppState& app,
                          std::span<const uint8_t> packet,
                          IPv6* destination) {
    if (packet.size() > app.config.mtu) {
        app.data_metrics.drop_oversized.fetch_add(1);
        return false;
    }
    if (packet.size() < 40 || (packet[0] >> 4) != 6) {
        app.data_metrics.drop_invalid_ipv6.fetch_add(1);
        return false;
    }

    const std::size_t declared_size =
        40 + (static_cast<std::size_t>(packet[4]) << 8) + packet[5];
    if (declared_size != packet.size()) {
        app.data_metrics.drop_invalid_ipv6.fetch_add(1);
        return false;
    }

    IPv6 parsed_destination{};
    std::copy_n(packet.begin() + 24,
                parsed_destination.size(),
                parsed_destination.begin());
    if (!std::equal(app.config.network.begin(),
                    app.config.network.begin() + 8,
                    parsed_destination.begin())) {
        app.data_metrics.drop_wrong_destination.fetch_add(1);
        return false;
    }
    if (destination) {
        *destination = parsed_destination;
    }
    return true;
}

bool local_ipv6_for_node(const AppState& app,
                         const NodeId& node,
                         const IPv6& address) {
    return virtual_address(app.config.network, node) == address;
}

struct IPv6TransportInfo {
    uint8_t protocol{0};
    uint16_t src_port{0};
    uint16_t dst_port{0};
    bool valid_ports{false};
};

IPv6TransportInfo parse_ipv6_transport(std::span<const uint8_t> packet) {
    IPv6TransportInfo info;
    if (packet.size() < 40 || (packet[0] >> 4) != 6) {
        return info;
    }
    uint8_t next_header = packet[6];
    std::size_t offset = 40;

    while (offset < packet.size()) {
        if (next_header == 6 || next_header == 17) {
            info.protocol = next_header;
            if (offset + 4 <= packet.size()) {
                info.src_port = static_cast<uint16_t>(
                    (static_cast<uint16_t>(packet[offset]) << 8) |
                    packet[offset + 1]);
                info.dst_port = static_cast<uint16_t>(
                    (static_cast<uint16_t>(packet[offset + 2]) << 8) |
                    packet[offset + 3]);
                info.valid_ports = true;
            }
            return info;
        }
        if (next_header == 58) {
            info.protocol = 58;
            return info;
        }
        if (next_header == 0 || next_header == 43 || next_header == 60) {
            if (offset + 2 > packet.size()) {
                break;
            }
            next_header = packet[offset];
            const std::size_t hdr_len =
                (static_cast<std::size_t>(packet[offset + 1]) + 1) * 8;
            offset += hdr_len;
        } else if (next_header == 44) {
            if (offset + 8 > packet.size()) {
                break;
            }
            next_header = packet[offset];
            offset += 8;
        } else if (next_header == 51) {
            if (offset + 2 > packet.size()) {
                break;
            }
            next_header = packet[offset];
            const std::size_t hdr_len =
                (static_cast<std::size_t>(packet[offset + 1]) + 2) * 4;
            offset += hdr_len;
        } else {
            info.protocol = next_header;
            return info;
        }
    }
    info.protocol = next_header;
    return info;
}

bool forward_data_packet(AppState& app,
                         DataPacket& packet,
                         bool origin,
                         std::string* error) {
    RoutingTable snapshot = routing_init();
    if (packet.destination != app.identity.id) {
        std::lock_guard<std::mutex> lock(app.routing_mutex);
        if (const auto* route =
                routing_find_route(app.routing_table, packet.destination)) {
            snapshot.routes.push_back(*route);
        }
    }

    auto forwarding = forwarding_init(&snapshot, &app.identity.id);
    forwarding_set_local_delivery_handler(
        &forwarding, [&](const DataPacket& delivered) {
            if (!app.config.share_all_ports) {
                const auto trans = parse_ipv6_transport(delivered.payload);
                if (trans.protocol == 58) {
                } else if (trans.valid_ports) {
                    bool allowed = is_port_shared(app.config, trans.dst_port);
                    if (!allowed) {
                        const auto now = std::chrono::steady_clock::now();
                        std::lock_guard<std::mutex> lock(
                            app.outbound_ports_mutex);
                        auto it =
                            app.active_outbound_ports.find(trans.dst_port);
                        if (it != app.active_outbound_ports.end()) {
                            if (now - it->second <= std::chrono::seconds{120}) {
                                allowed = true;
                                it->second = now;
                            } else {
                                app.active_outbound_ports.erase(it);
                            }
                        }
                    }
                    if (!allowed) {
                        app.data_metrics.drop_unshared_port.fetch_add(1);
                        return;
                    }
                } else {
                    app.data_metrics.drop_unshared_port.fetch_add(1);
                    return;
                }
            }

            std::lock_guard<std::mutex> lock(app.tun_write_mutex);
            if (!platform::tun_write_packet(
                    &app.vnet.tun, delivered.payload, error)) {
                app.data_metrics.drop_transport_error.fetch_add(1);
                return;
            }
            app.data_metrics.tun_packets_written.fetch_add(1);
            app.routing_metrics.delivered_local_packets.fetch_add(1);
            ++app.vnet.packets_received;
        });
    forwarding_set_transmit_handler(
        &forwarding, [&](const NodeId& next_hop, const DataPacket& forwarded) {
            auto session = find_session_by_next_hop(app, next_hop);
            if (!session) {
                app.routing_metrics.drop_next_hop_unavailable.fetch_add(1);
                return;
            }
            const Message wire{.type = MessageType::Data,
                               .payload = serialize_packet(forwarded)};
            std::string send_error;
            if (!send_on_session(session, wire, &send_error)) {
                app.data_metrics.drop_transport_error.fetch_add(1);
                return;
            }
            app.data_metrics.data_messages_sent.fetch_add(1);
            app.routing_metrics.forwarded_packets.fetch_add(1);
            if (origin) {
                ++app.vnet.packets_transmitted;
            }
        });
    forwarding_set_drop_handler(
        &forwarding, [&](const DataPacket&, std::string_view reason) {
            if (reason == "TTL expired") {
                app.routing_metrics.drop_ttl_expired.fetch_add(1);
            } else if (reason == "No route to destination") {
                app.routing_metrics.drop_no_route.fetch_add(1);
            }
        });
    if (origin) {
        forwarding_forward_origin(&forwarding, &packet);
    } else {
        forwarding_forward(&forwarding, &packet);
    }
    return forwarding.last_action != ForwardAction::DropNoRoute &&
           forwarding.last_action != ForwardAction::DropTtlExpired;
}

bool handle_data_message(AppState& app,
                         const Message& wire,
                         std::string* error) {
    DataPacket packet{};
    if (!deserialize_packet(wire.payload, &packet, error) ||
        packet.type != PacketType::DATA || packet.requires_ack) {
        app.data_metrics.drop_malformed_data_message.fetch_add(1);
        return false;
    }
    app.data_metrics.data_messages_received.fetch_add(1);

    IPv6 destination{};
    if (!validate_ipv6_packet(app, packet.payload, &destination) ||
        !local_ipv6_for_node(app, packet.destination, destination)) {
        app.data_metrics.drop_wrong_destination.fetch_add(1);
        return true;
    }

    IPv6 source{};
    std::copy_n(packet.payload.begin() + 8, source.size(), source.begin());
    if (!local_ipv6_for_node(app, packet.source, source)) {
        app.data_metrics.drop_invalid_ipv6.fetch_add(1);
        return true;
    }
    forward_data_packet(app, packet, false, error);
    return true;
}

void data_plane_loop(AppState* app) {
    std::vector<unsigned char> buffer(MAX_DATA_PAYLOAD_LIMIT);
    while (app->running.load(std::memory_order_relaxed) &&
           !core::lifecycle_is_stop_requested()) {
        const std::size_t packet_size = platform::tun_read_packet(
            &app->vnet.tun, buffer, std::chrono::milliseconds{200}, nullptr);
        if (packet_size == 0) {
            continue;
        }
        app->data_metrics.tun_packets_read.fetch_add(1);

        IPv6 destination{};
        const std::span<const uint8_t> raw_packet(buffer.data(), packet_size);
        if (!validate_ipv6_packet(*app, raw_packet, &destination) ||
            destination == app->vnet.address) {
            if (destination == app->vnet.address) {
                app->data_metrics.drop_wrong_destination.fetch_add(1);
            }
            continue;
        }

        const auto destination_node =
            resolve_node_by_virtual_address(*app, destination);
        if (!destination_node.has_value() ||
            *destination_node == app->identity.id) {
            app->routing_metrics.drop_no_route.fetch_add(1);
            continue;
        }

        IPv6 source{};
        std::copy_n(raw_packet.begin() + 8, source.size(), source.begin());
        if (source != app->vnet.address) {
            app->data_metrics.drop_invalid_ipv6.fetch_add(1);
            continue;
        }

        const auto trans = parse_ipv6_transport(raw_packet);
        if (trans.valid_ports) {
            const auto now = std::chrono::steady_clock::now();
            std::lock_guard<std::mutex> lock(app->outbound_ports_mutex);
            app->active_outbound_ports[trans.src_port] = now;
            if (app->active_outbound_ports.size() > 512) {
                for (auto it = app->active_outbound_ports.begin();
                     it != app->active_outbound_ports.end();) {
                    if (now - it->second > std::chrono::seconds{120}) {
                        it = app->active_outbound_ports.erase(it);
                    } else {
                        ++it;
                    }
                }
            }
        }

        DataPacket data = data_packet_create(
            PacketType::DATA,
            app->identity.id,
            *destination_node,
            app->next_packet_id.fetch_add(1, std::memory_order_relaxed),
            64,
            false,
            0,
            std::vector<uint8_t>(raw_packet.begin(), raw_packet.end()));
        std::string error;
        forward_data_packet(*app, data, true, &error);
    }
}

void start_data_plane_worker(AppState& app) {
    if (!app.data_plane_worker.joinable()) {
        app.data_plane_worker = std::thread(data_plane_loop, &app);
    }
}

void routing_loop(AppState* app) {
    using Clock = std::chrono::steady_clock;
    const auto interval = std::chrono::seconds{2};
    auto next_advertisement = Clock::now();
    auto next_hello = Clock::now();

    while (app->running.load(std::memory_order_relaxed) &&
           !core::lifecycle_is_stop_requested()) {
        bool dirty = false;
        {
            std::unique_lock<std::mutex> lock(app->routing_wakeup_mutex);
            app->routing_wakeup.wait_for(
                lock, std::chrono::milliseconds{100}, [&] {
                    return app->routing_dirty ||
                           !app->running.load(std::memory_order_relaxed);
                });
            dirty = app->routing_dirty;
            app->routing_dirty = false;
        }
        if (!app->running.load(std::memory_order_relaxed)) {
            break;
        }

        const uint64_t now = steady_now_ms();
        bool topology_changed = false;
        {
            std::lock_guard<std::mutex> lock(app->topology_mutex);
            const auto pruned = topology_prune_stale(&app->topology, now, 5000);
            topology_changed = pruned != 0;
            app->routing_metrics.neighbor_down.fetch_add(pruned);
        }

        bool advertisements_expired = false;
        {
            std::lock_guard<std::mutex> lock(app->routing_mutex);
            for (auto it = app->route_advertisements.begin();
                 it != app->route_advertisements.end();) {
                if (now > it->second.received_at_ms &&
                    now - it->second.received_at_ms >=
                        ROUTE_ADVERTISEMENT_TIMEOUT_MS) {
                    it = app->route_advertisements.erase(it);
                    app->routing_metrics.routes_expired.fetch_add(1);
                    advertisements_expired = true;
                } else {
                    ++it;
                }
            }
        }
        if (topology_changed || advertisements_expired) {
            rebuild_routing_table(*app);
            update_status_file(*app);
            dirty = true;
        }

        const auto now_clock = Clock::now();
        const bool send_hello = now_clock >= next_hello;
        const bool send_advertisement =
            dirty || now_clock >= next_advertisement;
        if (!send_hello && !send_advertisement) {
            continue;
        }

        const auto sessions = active_sessions(*app);
        for (const auto& session : sessions) {
            std::string error;
            if (send_hello) {
                const auto hello =
                    heartbeat_create_hello(app->identity.id, now);
                if (send_control(session,
                                 ControlMessageType::HELLO,
                                 app->next_control_sequence.fetch_add(
                                     1, std::memory_order_relaxed),
                                 app->identity.id,
                                 serialize_hello_message(hello),
                                 &error)) {
                }
            }
            if (send_advertisement) {
                RouteTable snapshot;
                RouteAdvertisement advertisement;
                {
                    std::lock_guard<std::mutex> lock(app->routing_mutex);
                    snapshot = app->routing_table;
                    advertisement = route_create_advertisement(
                        app->identity.id,
                        snapshot,
                        app->next_route_sequence++,
                        session->peer_id,
                        SplitHorizonMode::PoisonReverse);
                    advertisement.generation = app->identity.generation;
                }
                if (send_control(session,
                                 ControlMessageType::ROUTE_ADVERTISEMENT,
                                 app->next_control_sequence.fetch_add(
                                     1, std::memory_order_relaxed),
                                 app->identity.id,
                                 serialize_route_advertisement(advertisement),
                                 &error)) {
                    app->routing_metrics.route_advertisements_sent.fetch_add(1);
                }
            }
        }
        if (send_hello) {
            next_hello = Clock::now() + interval;
        }
        if (send_advertisement) {
            next_advertisement = Clock::now() + interval;
            update_status_file(*app);
        }
    }
}

void start_routing_worker(AppState& app) {
    if (!app.routing_worker.joinable()) {
        app.routing_worker = std::thread(routing_loop, &app);
    }
}

void run_session(AppState* app, std::shared_ptr<AppPeerSession> session) {
    const auto refresh_interval = std::chrono::seconds{5};
    const auto admission_deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds{3};
    auto next_refresh = std::chrono::steady_clock::now() + refresh_interval;
    auto message_window = std::chrono::steady_clock::now();
    std::size_t messages_in_window = 0;
    uint64_t refresh_sequence = 10000;

    while (app->running.load(std::memory_order_relaxed) &&
           !core::lifecycle_is_stop_requested() && session_is_open(session)) {
        if (!session->trusted &&
            std::chrono::steady_clock::now() >= admission_deadline) {
            break;
        }
        Message wire{};
        bool closed = false;
        std::string error;
        const bool received = receive_on_session(
            session, &wire, std::chrono::milliseconds{200}, &closed, &error);
        if (!received) {
            if (closed || !session_is_open(session)) {
                break;
            }
            bool has_peer = false;
            {
                std::lock_guard<std::mutex> lock(app->sessions_mutex);
                has_peer = session->peer_id.has_value();
            }
            if (has_peer && session->trusted &&
                std::chrono::steady_clock::now() >= next_refresh) {
                const FindNodeMessage request{.target = app->identity.id};
                if (!send_control(session,
                                  ControlMessageType::FIND_NODE,
                                  refresh_sequence++,
                                  app->identity.id,
                                  serialize_find_node(request),
                                  &error)) {
                    break;
                }
                next_refresh =
                    std::chrono::steady_clock::now() + refresh_interval;
            }
            continue;
        }

        const auto received_at = std::chrono::steady_clock::now();
        if (received_at - message_window >= std::chrono::seconds{1}) {
            message_window = received_at;
            messages_in_window = 0;
        }
        if (++messages_in_window > MAX_MESSAGES_PER_SECOND) {
            break;
        }

        if (wire.type == MessageType::Data) {
            if (!session->trusted) {
                break;
            }
            if (session->transport.peer_node_id.has_value()) {
                touch_neighbor(*app, *session->transport.peer_node_id);
            }
            if (!handle_data_message(*app, wire, &error)) {
                break;
            }
            continue;
        }

        if (wire.type != MessageType::Control) {
            continue;
        }

        ControlMessage incoming{};
        if (!deserialize_control_message(wire.payload, &incoming, &error)) {
            break;
        }
        if (!session->transport.peer_node_id.has_value() ||
            incoming.sender != *session->transport.peer_node_id) {
            break;
        }

        if (!session->trusted &&
            incoming.type != ControlMessageType::JOIN_REQUEST) {
            break;
        }

        if (incoming.type == ControlMessageType::JOIN_REQUEST) {
            JoinRequest request{};
            std::string endpoint_host;
            uint16_t endpoint_port = 0;
            if (!deserialize_join_request(incoming.payload, &request, &error) ||
                request.node_id != *session->transport.peer_node_id ||
                request.public_key != session->transport.tls.peer_pubkey ||
                request.virtual_address !=
                    virtual_address(app->config.network, request.node_id) ||
                !parse_endpoint(
                    request.endpoint, &endpoint_host, &endpoint_port) ||
                endpoint_port == 0) {
                break;
            }

            bool admitted = false;
            {
                std::lock_guard<std::mutex> lock(app->trust_mutex);
                const TrustedPeer* known =
                    trust_find(app->trust, request.node_id);
                const bool key_matches =
                    known == nullptr || known->public_key == request.public_key;
                if (known != nullptr && request.invite_token.empty() &&
                    key_matches) {
                    admitted = true;
                } else if (key_matches && !request.invite_token.empty() &&
                           trust_address_available(app->trust,
                                                   app->config.network,
                                                   app->identity.id,
                                                   request.node_id)) {
                    InviteTicket invitation{};
                    admitted = invite_decode(
                                   request.invite_token, &invitation, &error) &&
                               invite_consume(app->trust,
                                              invitation,
                                              app->identity.id,
                                              now_ms() / 1000,
                                              &error);
                }
                if (admitted) {
                    admitted =
                        trust_add(&app->trust,
                                  TrustedPeer{.id = request.node_id,
                                              .public_key = request.public_key,
                                              .endpoint = request.endpoint},
                                  &error);
                }
            }
            if (!admitted) {
                JoinResponse rejected{
                    .accepted = false,
                    .bootstrap_contact = app->local_contact,
                    .bootstrap_id = app->identity.id,
                };
                send_control(session,
                             ControlMessageType::JOIN_RESPONSE,
                             incoming.sequence_number,
                             app->identity.id,
                             serialize_join_response(rejected));
                break;
            }
            session->trusted = true;
        }

        if (!session->trusted) {
            break;
        }

        touch_neighbor(*app, incoming.sender);

        if (incoming.type == ControlMessageType::HELLO) {
            HelloMessage hello{};
            if (!deserialize_hello_message(incoming.payload, &hello, &error) ||
                hello.sender != incoming.sender) {
                break;
            }
            std::lock_guard<std::mutex> lock(app->topology_mutex);
            heartbeat_process_hello(&app->topology, hello, steady_now_ms());
            continue;
        }

        if (incoming.type == ControlMessageType::ROUTE_ADVERTISEMENT) {
            RouteAdvertisement advertisement{};
            if (!deserialize_route_advertisement(
                    incoming.payload, &advertisement, &error) ||
                advertisement.sender != incoming.sender ||
                !validate_route_advertisement(
                    advertisement, app->config.network, &error)) {
                app->routing_metrics.drop_invalid_route_advertisement.fetch_add(
                    1);
                break;
            }
            app->routing_metrics.route_advertisements_received.fetch_add(1);
            bool accepted = false;
            bool changed = false;
            {
                std::lock_guard<std::mutex> lock(app->routing_mutex);
                accepted = distance_vector_update(app->routing_table,
                                                  incoming.sender,
                                                  advertisement,
                                                  steady_now_ms(),
                                                  1,
                                                  &app->route_origins,
                                                  &changed);
                if (accepted) {
                    app->route_advertisements[incoming.sender] =
                        StoredRouteAdvertisement{.advertisement = advertisement,
                                                 .received_at_ms =
                                                     steady_now_ms()};
                }
            }
            if (!accepted) {
                app->routing_metrics.route_advertisements_stale.fetch_add(1);
                continue;
            }
            if (!changed) {
                continue;
            }
            rebuild_routing_table(*app);
            mark_routing_dirty(*app);
            update_status_file(*app);
            continue;
        }

        if (incoming.type == ControlMessageType::NEIGHBORS) {
            NeighborsMessage neighbors{};
            if (!deserialize_neighbors(incoming.payload, &neighbors, &error) ||
                !std::all_of(neighbors.peers.begin(),
                             neighbors.peers.end(),
                             [&](const NodeContact& contact) {
                                 return valid_node_contact(app->config,
                                                           contact);
                             })) {
                break;
            }
            std::lock_guard<std::mutex> lock(app->kademlia_mutex);
            handle_neighbors(app->kademlia_table, neighbors);
            continue;
        }

        if (incoming.type == ControlMessageType::NODE_ANNOUNCE) {
            NodeAnnounceMessage announce{};
            if (!deserialize_node_announce(
                    incoming.payload, &announce, &error) ||
                announce.contact.id != *session->transport.peer_node_id ||
                announce.contact.public_key !=
                    session->transport.tls.peer_pubkey ||
                announce.contact.virtual_address !=
                    virtual_address(app->config.network, announce.contact.id)) {
                break;
            }
        }

        if (incoming.type != ControlMessageType::JOIN_REQUEST &&
            incoming.type != ControlMessageType::FIND_NODE &&
            incoming.type != ControlMessageType::NODE_ANNOUNCE) {
            continue;
        }

        ControlMessage reply{};
        {
            std::lock_guard<std::mutex> lock(app->kademlia_mutex);
            if (!dispatch_join_protocol_message(app->kademlia_table,
                                                incoming,
                                                &reply,
                                                &app->local_contact,
                                                true)) {
                break;
            }
        }

        if (!send_on_session(session, make_control_wire(reply), &error)) {
            break;
        }

        if (incoming.type == ControlMessageType::JOIN_REQUEST) {
            JoinRequest request{};
            JoinResponse response{};
            if (deserialize_join_request(incoming.payload, &request) &&
                deserialize_join_response(reply.payload, &response) &&
                response.accepted) {
                const NodeContact contact{
                    .id = request.node_id,
                    .public_key = request.public_key,
                    .virtual_address = request.virtual_address,
                    .endpoint = request.endpoint,
                    .last_seen_ms = request.timestamp,
                };
                if (!bind_session(*app, session, contact)) {
                    break;
                }
            }
        } else if (incoming.type == ControlMessageType::NODE_ANNOUNCE) {
            NodeAnnounceMessage announce{};
            NodeAnnounceAck ack{};
            if (deserialize_node_announce(incoming.payload, &announce) &&
                deserialize_node_announce_ack(reply.payload, &ack) &&
                ack.accepted &&
                !bind_session(*app, session, announce.contact)) {
                break;
            }
        }
    }

    close_session(session);
    remove_session(*app, session);
}

std::vector<NodeContact> query_peer(AppState& app,
                                    const NodeId& peer_id,
                                    const NodeId& target,
                                    uint64_t sequence) {
    auto session = find_idle_session(app, peer_id);
    if (!session) {
        NodeContact contact{};
        {
            std::lock_guard<std::mutex> lock(app.kademlia_mutex);
            const auto* found = kademlia_find(app.kademlia_table, peer_id);
            if (!found) {
                return {};
            }
            contact = *found;
        }

        std::string host;
        uint16_t port = 0;
        if (!parse_endpoint(contact.endpoint, &host, &port) || port == 0) {
            return {};
        }

        auto new_session = std::make_shared<AppPeerSession>();
        std::string error;
        if (!peer_is_trusted(app, peer_id) ||
            !transport_connect_tls(&new_session->transport,
                                   tls_config_for(app),
                                   host,
                                   port,
                                   peer_id,
                                   std::chrono::milliseconds{3000},
                                   &error)) {
            return {};
        }
        new_session->trusted = true;
        new_session->peer_id = peer_id;
        new_session->contact = contact;
        if (!register_session(app, new_session) ||
            !activate_neighbor(app, contact)) {
            remove_session(app, new_session);
            close_session(new_session);
            return {};
        }
        session = std::move(new_session);
    }

    FindNodeMessage request{.target = target};
    std::string error;
    if (!send_control(session,
                      ControlMessageType::FIND_NODE,
                      sequence,
                      app.identity.id,
                      serialize_find_node(request),
                      &error)) {
        remove_session(app, session);
        close_session(session);
        return {};
    }

    ControlMessage reply{};
    if (!receive_control(
            session, &reply, std::chrono::milliseconds{3000}, &error) ||
        reply.type != ControlMessageType::NEIGHBORS ||
        reply.sender != peer_id) {
        remove_session(app, session);
        close_session(session);
        return {};
    }

    NeighborsMessage neighbors{};
    if (!deserialize_neighbors(reply.payload, &neighbors, &error) ||
        !std::all_of(neighbors.peers.begin(),
                     neighbors.peers.end(),
                     [&](const NodeContact& contact) {
                         return valid_node_contact(app.config, contact);
                     })) {
        remove_session(app, session);
        close_session(session);
        return {};
    }
    return neighbors.peers;
}

bool announce_to_peer(AppState& app,
                      const std::shared_ptr<AppPeerSession>& session,
                      uint64_t sequence) {
    std::string error;
    NodeAnnounceMessage announce{.contact = app.local_contact,
                                 .nonce = sequence};
    if (!send_control(session,
                      ControlMessageType::NODE_ANNOUNCE,
                      sequence,
                      app.identity.id,
                      serialize_node_announce(announce),
                      &error)) {
        return false;
    }

    ControlMessage reply{};
    if (!receive_control(
            session, &reply, std::chrono::milliseconds{3000}, &error) ||
        reply.type != ControlMessageType::NODE_ANNOUNCE_ACK ||
        !session->peer_id.has_value() || reply.sender != *session->peer_id) {
        return false;
    }

    NodeAnnounceAck ack{};
    return deserialize_node_announce_ack(reply.payload, &ack, &error) &&
           ack.accepted;
}

void start_all_session_workers(AppState& app) {
    std::vector<std::shared_ptr<AppPeerSession>> sessions;
    {
        std::lock_guard<std::mutex> lock(app.sessions_mutex);
        sessions = app.sessions;
    }
    for (const auto& session : sessions) {
        start_session_worker(app, session);
    }
}

void update_status_file(AppState& app) {
    if (app.config_path.empty()) {
        return;
    }
    static std::mutex status_mutex;
    std::lock_guard<std::mutex> status_lock(status_mutex);

    std::vector<Peer> peers;
    {
        std::lock_guard<std::mutex> lock(app.topology_mutex);
        peers = app.topology.peers;
    }
    std::vector<Route> routes;
    {
        std::lock_guard<std::mutex> lock(app.routing_mutex);
        routes = app.routing_table.routes;
    }

    std::ostringstream out;
    out << "NODE_ID=" << hex(app.identity.id) << "\n";
    out << "UPDATED=" << now_ms() << "\n";
    out << "NETWORK=" << format_ipv6(app.config.network) << "/64\n";
    out << "LISTEN=" << app.local_contact.endpoint << "\n";
    {
        std::lock_guard<std::mutex> lock(app.trust_mutex);
        out << "TRUSTED=" << app.trust.peers.size() << "\n";
    }

    for (const auto& peer : peers) {
        if (peer.state == PeerState::Connected) {
            out << "PEER=" << hex(peer.id) << " connected Trusted\n";
        }
    }
    for (const auto& route : routes) {
        if (route.destination_node != NodeId{}) {
            out << "ROUTE=" << hex(route.destination_node) << " via "
                << hex(route.next_hop) << " metric " << route.metric << "\n";
        }
    }

    const uint64_t total_packets = app.data_metrics.tun_packets_read.load() +
                                   app.data_metrics.tun_packets_written.load();
    const uint64_t dropped = app.routing_metrics.drop_no_route.load() +
                             app.routing_metrics.drop_ttl_expired.load() +
                             app.data_metrics.drop_transport_error.load();
    double loss_rate = 0.0;
    if (total_packets + dropped > 0) {
        loss_rate = (static_cast<double>(dropped) /
                     static_cast<double>(total_packets + dropped)) *
                    100.0;
    }

    out << "PACKETS=" << total_packets << "\n";
    out << "LOSS=" << std::fixed << std::setprecision(1) << loss_rate << "%\n";

    if (app.config.share_all_ports) {
        out << "SHARED_PORTS=all\n";
    } else if (app.config.shared_ports.empty()) {
        out << "SHARED_PORTS=none\n";
    } else {
        out << "SHARED_PORTS=";
        for (std::size_t i = 0; i < app.config.shared_ports.size(); ++i) {
            if (i > 0) {
                out << ",";
            }
            out << app.config.shared_ports[i];
        }
        out << "\n";
    }

    std::string ignored;
    platform::private_write_atomically(
        std::filesystem::path{app.config_path.string() + ".status"},
        out.str(),
        &ignored);
}

void reconnect_step(AppState& app) {
    if (!app.running.load(std::memory_order_relaxed) ||
        core::lifecycle_is_stop_requested()) {
        return;
    }

    std::vector<TrustedPeer> targets;
    {
        std::lock_guard<std::mutex> lock(app.trust_mutex);
        targets = app.trust.peers;
    }

    for (const auto& target : targets) {
        if (!(app.identity.id < target.id)) {
            continue;
        }
        if (!app.running.load(std::memory_order_relaxed) ||
            core::lifecycle_is_stop_requested()) {
            break;
        }

        std::string host;
        uint16_t port = 0;
        if (!parse_endpoint(target.endpoint, &host, &port) || port == 0) {
            continue;
        }

        bool already_connected = false;
        {
            std::lock_guard<std::mutex> lock(app.sessions_mutex);
            for (const auto& sess : app.sessions) {
                if (session_is_open(sess)) {
                    if ((sess->peer_id.has_value() &&
                         *sess->peer_id == target.id) ||
                        sess->contact.endpoint == target.endpoint) {
                        already_connected = true;
                        break;
                    }
                }
            }
        }
        if (already_connected) {
            continue;
        }

        auto session = std::make_shared<AppPeerSession>();
        std::string error;
        if (!transport_connect_tls(&session->transport,
                                   tls_config_for(app),
                                   host,
                                   port,
                                   target.id,
                                   std::chrono::milliseconds{1000},
                                   &error)) {
            continue;
        }

        if (!session->transport.peer_node_id.has_value() ||
            *session->transport.peer_node_id != target.id ||
            session->transport.tls.peer_pubkey != target.public_key) {
            close_session(session);
            continue;
        }

        const NodeId peer_id = *session->transport.peer_node_id;
        {
            std::lock_guard<std::mutex> lock(app.sessions_mutex);
            bool has_peer = false;
            for (const auto& sess : app.sessions) {
                if (sess->peer_id.has_value() && *sess->peer_id == peer_id &&
                    session_is_open(sess)) {
                    has_peer = true;
                    break;
                }
            }
            if (has_peer) {
                close_session(session);
                continue;
            }
        }

        JoinRequest join_request{
            .node_id = app.identity.id,
            .public_key = app.local_contact.public_key,
            .virtual_address = app.local_contact.virtual_address,
            .endpoint = app.local_contact.endpoint,
            .timestamp = now_ms(),
            .nonce = 1001,
        };
        if (!send_control(session,
                          ControlMessageType::JOIN_REQUEST,
                          app.next_control_sequence.fetch_add(
                              1, std::memory_order_relaxed),
                          app.identity.id,
                          serialize_join_request(join_request),
                          &error)) {
            close_session(session);
            continue;
        }

        ControlMessage reply{};
        if (!receive_control(
                session, &reply, std::chrono::milliseconds{1500}, &error) ||
            reply.type != ControlMessageType::JOIN_RESPONSE ||
            reply.sender != peer_id) {
            close_session(session);
            continue;
        }

        JoinResponse join_response{};
        if (!deserialize_join_response(reply.payload, &join_response, &error) ||
            !join_response.accepted) {
            close_session(session);
            continue;
        }

        NodeContact peer_contact = join_response.bootstrap_contact;
        if ((peer_contact.id != NodeId{} && peer_contact.id != peer_id) ||
            (peer_contact.public_key != std::array<uint8_t, 32>{} &&
             peer_contact.public_key != target.public_key) ||
            (peer_contact.virtual_address != IPv6{} &&
             peer_contact.virtual_address !=
                 virtual_address(app.config.network, peer_id))) {
            close_session(session);
            continue;
        }
        peer_contact.id = peer_id;
        peer_contact.public_key = target.public_key;
        peer_contact.endpoint = target.endpoint;
        if (peer_contact.virtual_address == IPv6{}) {
            peer_contact.virtual_address =
                virtual_address(app.config.network, peer_id);
        }

        session->trusted = true;
        session->peer_id = peer_id;
        session->contact = peer_contact;
        if (!register_session(app, session) ||
            !activate_neighbor(app, peer_contact)) {
            remove_session(app, session);
            close_session(session);
            continue;
        }

        start_session_worker(app, session);
        mark_routing_dirty(app);
        update_status_file(app);
    }
}

void reconnect_loop(AppState* app) {
    int interval_ms = 500;
    while (app->running.load(std::memory_order_relaxed) &&
           !core::lifecycle_is_stop_requested()) {
        reconnect_step(*app);
        update_status_file(*app);
        for (int i = 0; i < interval_ms / 100 &&
                        app->running.load(std::memory_order_relaxed) &&
                        !core::lifecycle_is_stop_requested();
             ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds{100});
        }
        if (interval_ms < 2000) {
            interval_ms += 500;
        }
    }
}

void start_reconnect_worker(AppState& app) {
    if (!app.reconnect_worker.joinable()) {
        app.reconnect_worker = std::thread(reconnect_loop, &app);
    }
}

int wait_for_shutdown(AppState* app) {
    while (app->running.load(std::memory_order_relaxed) &&
           !core::lifecycle_is_stop_requested()) {
        std::this_thread::sleep_for(std::chrono::milliseconds{100});
    }
    if (app->node_state == NodeState::ACTIVE) {
        std::string error;
        node_state_transition(app->node_state, NodeState::LEAVING, &error);
    }
    app_shutdown(app);
    std::cout
        << "data_metrics"
        << " tun_packets_read=" << app->data_metrics.tun_packets_read.load()
        << " tun_packets_written="
        << app->data_metrics.tun_packets_written.load()
        << " data_messages_sent=" << app->data_metrics.data_messages_sent.load()
        << " data_messages_received="
        << app->data_metrics.data_messages_received.load()
        << " drop_no_active_peer="
        << app->data_metrics.drop_no_active_peer.load()
        << " drop_invalid_ipv6=" << app->data_metrics.drop_invalid_ipv6.load()
        << " drop_wrong_destination="
        << app->data_metrics.drop_wrong_destination.load()
        << " drop_oversized=" << app->data_metrics.drop_oversized.load()
        << " drop_transport_error="
        << app->data_metrics.drop_transport_error.load()
        << " drop_malformed_data_message="
        << app->data_metrics.drop_malformed_data_message.load()
        << " routes_installed=" << app->routing_metrics.routes_installed.load()
        << " routes_updated=" << app->routing_metrics.routes_updated.load()
        << " routes_expired=" << app->routing_metrics.routes_expired.load()
        << " route_advertisements_sent="
        << app->routing_metrics.route_advertisements_sent.load()
        << " route_advertisements_received="
        << app->routing_metrics.route_advertisements_received.load()
        << " route_advertisements_stale="
        << app->routing_metrics.route_advertisements_stale.load()
        << " forwarded_packets="
        << app->routing_metrics.forwarded_packets.load()
        << " delivered_local_packets="
        << app->routing_metrics.delivered_local_packets.load()
        << " drop_no_route=" << app->routing_metrics.drop_no_route.load()
        << " drop_next_hop_unavailable="
        << app->routing_metrics.drop_next_hop_unavailable.load()
        << " drop_ttl_expired=" << app->routing_metrics.drop_ttl_expired.load()
        << " drop_invalid_route_advertisement="
        << app->routing_metrics.drop_invalid_route_advertisement.load()
        << " neighbor_up=" << app->routing_metrics.neighbor_up.load()
        << " neighbor_down=" << app->routing_metrics.neighbor_down.load()
        << '\n';
    std::cout << "Madoka Mesh stopped.\n";
    return 0;
}

int run_join(AppState* app) {
    std::string error;
    if (!node_state_transition(
            app->node_state, NodeState::DISCOVERING, &error)) {
        std::cerr << "State transition error: " << error << '\n';
        return 1;
    }
    std::cout << "state=DISCOVERING\n" << std::flush;

    std::string bootstrap_host;
    uint16_t bootstrap_port = 0;
    if (!parse_endpoint(
            app->bootstrap_endpoint, &bootstrap_host, &bootstrap_port) ||
        bootstrap_port == 0) {
        std::cerr << "Invalid bootstrap endpoint: " << app->bootstrap_endpoint
                  << '\n';
        return 1;
    }

    std::array<uint8_t, 32> public_key{};
    if (!extract_public_key(app->identity, public_key)) {
        std::cerr << "Failed to export Ed25519 public key.\n";
        return 1;
    }

    if (!start_runtime(*app, &error)) {
        std::cerr << "Runtime initialization error: " << error << '\n';
        app_shutdown(app);
        return 1;
    }

    if (!node_state_transition(
            app->node_state, NodeState::JOINING_NETWORK, &error)) {
        std::cerr << "State transition error: " << error << '\n';
        app_shutdown(app);
        return 1;
    }
    std::cout << "state=JOINING_NETWORK\n" << std::flush;

    auto bootstrap_session = std::make_shared<AppPeerSession>();
    if (!transport_connect_tls(&bootstrap_session->transport,
                               tls_config_for(*app),
                               bootstrap_host,
                               bootstrap_port,
                               app->join_invite.inviter_id,
                               std::chrono::milliseconds{5000},
                               &error)) {
        std::cerr << "Cannot connect to bootstrap at "
                  << app->bootstrap_endpoint << ": " << error << '\n';
        app_shutdown(app);
        return 1;
    }
    if (!bootstrap_session->transport.peer_node_id.has_value() ||
        *bootstrap_session->transport.peer_node_id !=
            app->join_invite.inviter_id) {
        error = "Bootstrap identity does not match the invitation";
        std::cerr << error << '\n';
        close_session(bootstrap_session);
        app_shutdown(app);
        return 1;
    }

    JoinRequest join_request{
        .node_id = app->identity.id,
        .public_key = public_key,
        .virtual_address = app->local_contact.virtual_address,
        .endpoint = app->local_contact.endpoint,
        .timestamp = now_ms(),
        .nonce = 1001,
        .invite_token = app->join_token,
    };
    if (!send_control(bootstrap_session,
                      ControlMessageType::JOIN_REQUEST,
                      1,
                      app->identity.id,
                      serialize_join_request(join_request),
                      &error)) {
        std::cerr << "Failed to send JOIN_REQUEST: " << error << '\n';
        close_session(bootstrap_session);
        app_shutdown(app);
        return 1;
    }

    ControlMessage response_control{};
    if (!receive_control(bootstrap_session,
                         &response_control,
                         std::chrono::milliseconds{5000},
                         &error) ||
        response_control.type != ControlMessageType::JOIN_RESPONSE) {
        std::cerr << "Failed to receive JOIN_RESPONSE: " << error << '\n';
        close_session(bootstrap_session);
        app_shutdown(app);
        return 1;
    }

    JoinResponse join_response{};
    if (!deserialize_join_response(
            response_control.payload, &join_response, &error) ||
        !join_response.accepted) {
        std::cerr << "Bootstrap rejected JOIN_REQUEST.\n";
        close_session(bootstrap_session);
        app_shutdown(app);
        return 1;
    }

    NodeContact bootstrap_contact = join_response.bootstrap_contact;
    if (!bootstrap_session->transport.peer_node_id.has_value() ||
        response_control.sender != *bootstrap_session->transport.peer_node_id ||
        (bootstrap_contact.id != NodeId{} &&
         bootstrap_contact.id != response_control.sender) ||
        (join_response.bootstrap_id != NodeId{} &&
         join_response.bootstrap_id != response_control.sender) ||
        (bootstrap_contact.virtual_address != IPv6{} &&
         bootstrap_contact.virtual_address !=
             virtual_address(app->config.network, response_control.sender))) {
        std::cerr << "JOIN_RESPONSE identity does not match TLS peer.\n";
        close_session(bootstrap_session);
        app_shutdown(app);
        return 1;
    }
    if (bootstrap_contact.id == NodeId{}) {
        bootstrap_contact.id = response_control.sender;
    }
    if (bootstrap_contact.endpoint.empty()) {
        bootstrap_contact.endpoint = app->bootstrap_endpoint;
    }
    if (bootstrap_contact.id != response_control.sender ||
        bootstrap_contact.id == app->identity.id ||
        (bootstrap_contact.public_key != std::array<uint8_t, 32>{} &&
         bootstrap_contact.public_key !=
             bootstrap_session->transport.tls.peer_pubkey)) {
        std::cerr << "JOIN_RESPONSE has no valid bootstrap identity.\n";
        close_session(bootstrap_session);
        app_shutdown(app);
        return 1;
    }
    if (bootstrap_contact.public_key == std::array<uint8_t, 32>{}) {
        bootstrap_contact.public_key =
            bootstrap_session->transport.tls.peer_pubkey;
    }
    if (bootstrap_contact.virtual_address == IPv6{}) {
        bootstrap_contact.virtual_address =
            virtual_address(app->config.network, bootstrap_contact.id);
    }
    if (bootstrap_contact.endpoint != app->bootstrap_endpoint ||
        !valid_node_contact(app->config, bootstrap_contact) ||
        !std::all_of(join_response.peers.begin(),
                     join_response.peers.end(),
                     [&](const NodeContact& contact) {
                         return valid_node_contact(app->config, contact);
                     })) {
        std::cerr << "JOIN_RESPONSE contains an invalid network contact.\n";
        close_session(bootstrap_session);
        app_shutdown(app);
        return 1;
    }
    {
        std::lock_guard<std::mutex> lock(app->trust_mutex);
        if (!trust_address_available(app->trust,
                                     app->config.network,
                                     app->identity.id,
                                     bootstrap_contact.id)) {
            std::cerr << "Bootstrap address collision in network.\n";
            close_session(bootstrap_session);
            app_shutdown(app);
            return 1;
        }

        if (app->identity.storage_path.empty()) {
            if (!platform::private_ensure_directory(
                    app->config.identity_file.parent_path(), &error)) {
                std::cerr << "Cannot create state directory: " << error << '\n';
                close_session(bootstrap_session);
                app_shutdown(app);
                return 1;
            }
            if (!platform::private_ensure_directory(app->trust.directory,
                                                    &error)) {
                std::cerr << "Cannot create trust directory: " << error << '\n';
                close_session(bootstrap_session);
                app_shutdown(app);
                return 1;
            }
            if (!identity_save(
                    &app->identity, app->config.identity_file, &error)) {
                std::cerr << "Cannot persist identity: " << error << '\n';
                close_session(bootstrap_session);
                app_shutdown(app);
                return 1;
            }
            save_config(app->config_path, app->config);
        }

        if (!trust_add(
                &app->trust,
                TrustedPeer{.id = bootstrap_contact.id,
                            .public_key =
                                bootstrap_session->transport.tls.peer_pubkey,
                            .endpoint = bootstrap_contact.endpoint},
                &error)) {
            std::cerr << "Cannot persist bootstrap trust: " << error << '\n';
            close_session(bootstrap_session);
            app_shutdown(app);
            return 1;
        }
    }
    bootstrap_session->trusted = true;
    bootstrap_session->peer_id = bootstrap_contact.id;
    bootstrap_session->contact = bootstrap_contact;
    if (!register_session(*app, bootstrap_session) ||
        !activate_neighbor(*app, bootstrap_contact)) {
        std::cerr << "Cannot register bootstrap as an operational neighbor.\n";
        remove_session(*app, bootstrap_session);
        close_session(bootstrap_session);
        app_shutdown(app);
        return 1;
    }
    {
        std::lock_guard<std::mutex> lock(app->kademlia_mutex);
        handle_join_response(
            app->kademlia_table, join_response, bootstrap_contact);
    }

    uint64_t sequence = 2;
    auto query_fn = [&](const NodeId& peer,
                        const NodeId& target) -> std::vector<NodeContact> {
        return query_peer(*app, peer, target, sequence++);
    };
    kademlia_self_lookup(app->kademlia_table, query_fn, 3);

    std::vector<NodeContact> announce_contacts;
    {
        std::lock_guard<std::mutex> lock(app->kademlia_mutex);
        announce_contacts = kademlia_find_closest(
            app->kademlia_table, app->identity.id, KADEMLIA_K);
    }
    for (const auto& contact : announce_contacts) {
        if (contact.id == app->identity.id) {
            continue;
        }
        auto session = find_idle_session(*app, contact.id);
        if (!session) {
            continue;
        }
        if (!announce_to_peer(*app, session, sequence++)) {
            remove_session(*app, session);
            close_session(session);
        }
    }

    if (!node_state_transition(app->node_state, NodeState::ACTIVE, &error)) {
        std::cerr << "State transition error: " << error << '\n';
        app_shutdown(app);
        return 1;
    }

    std::cout << "state=ACTIVE\n"
              << "node_id=" << hex(app->identity.id) << '\n'
              << "listen=" << app->local_contact.endpoint << '\n'
              << "bootstrap=" << app->bootstrap_endpoint << '\n'
              << "kademlia_contacts=";
    {
        std::lock_guard<std::mutex> lock(app->kademlia_mutex);
        std::cout << kademlia_total_contacts(app->kademlia_table);
    }
    std::cout << "\nMadoka Mesh started.\n" << std::flush;

    start_all_session_workers(*app);
    start_accept_worker(*app);
    start_data_plane_worker(*app);
    start_routing_worker(*app);
    start_reconnect_worker(*app);
    update_status_file(*app);
    return wait_for_shutdown(app);
}

} // namespace

int daemon_run(AppState* app) {
    if (app->join_mode) {
        return run_join(app);
    }

    std::string error;
    if (!node_state_transition(
            app->node_state, NodeState::DISCOVERING, &error)) {
        std::cerr << "State transition error: " << error << '\n';
        app_shutdown(app);
        return 1;
    }
    if (!start_runtime(*app, &error)) {
        std::cerr << "Runtime initialization error: " << error << '\n';
        std::cout << "state=error\n";
        app_shutdown(app);
        return 1;
    }
    if (!node_state_transition(app->node_state, NodeState::ACTIVE, &error)) {
        std::cerr << "State transition error: " << error << '\n';
        app_shutdown(app);
        return 1;
    }

    std::cout << "state=interface_ready\n"
              << "state=ACTIVE\n"
              << "listen=" << app->local_contact.endpoint << '\n'
              << "kademlia_contacts=0\n"
              << "Madoka Mesh started (phase 2; virtual network ready).\n"
              << std::flush;
    start_accept_worker(*app);
    start_data_plane_worker(*app);
    start_routing_worker(*app);
    start_reconnect_worker(*app);
    update_status_file(*app);
    return wait_for_shutdown(app);
}

} // namespace madoka
