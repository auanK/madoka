#ifndef MADOKA_TRANSPORT_SESSION_HPP
#define MADOKA_TRANSPORT_SESSION_HPP

#include "crypto/tls.hpp"
#include "platform/socket.hpp"
#include "protocol/codec.hpp"
#include "protocol/message.hpp"
#include "transport/frame.hpp"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace madoka {

struct TransportSessionState {
    SocketHandle socket{};

    TlsSession tls{};

    bool is_tls{false};

    std::vector<uint8_t> recv_buffer{};

    std::string remote_endpoint{};

    std::optional<NodeId> peer_node_id{std::nullopt};

    std::atomic_bool is_open{false};
};

struct TransportServerState {
    SocketHandle listen_socket{};

    TlsContext tls_ctx{};

    bool is_tls{false};

    std::string bind_address{"::1"};

    uint16_t port{0};

    std::function<bool(const NodeId&)> peer_validator{nullptr};

    bool is_listening{false};
};

bool transport_server_init(TransportServerState* server,
                           uint16_t port,
                           std::string_view bind_address = "::1",
                           std::string* error = nullptr);

bool transport_server_init_tls(
    TransportServerState* server,
    const TlsConfig& config,
    uint16_t port,
    std::string_view bind_address = "::1",
    std::function<bool(const NodeId&)> peer_validator = nullptr,
    std::string* error = nullptr);

bool transport_server_start(TransportServerState* server,
                            std::string* error = nullptr);

void transport_server_close(TransportServerState* server);

uint16_t transport_server_local_port(const TransportServerState& server);

bool transport_accept(
    TransportServerState* server,
    TransportSessionState* out_session,
    std::optional<std::chrono::milliseconds> timeout = std::nullopt,
    std::string* error = nullptr);

bool transport_connect(
    TransportSessionState* session,
    std::string_view host,
    uint16_t port,
    std::chrono::milliseconds timeout = std::chrono::milliseconds{5000},
    std::string* error = nullptr);

bool transport_connect_tls(
    TransportSessionState* session,
    const TlsConfig& client_tls_config,
    std::string_view host,
    uint16_t port,
    std::optional<NodeId> expected_peer_id = std::nullopt,
    std::chrono::milliseconds timeout = std::chrono::milliseconds{5000},
    std::string* error = nullptr);

bool transport_send(TransportSessionState* session,
                    const Message& message,
                    std::string* error = nullptr);

bool transport_receive(
    TransportSessionState* session,
    Message* out_message,
    std::optional<std::chrono::milliseconds> timeout = std::nullopt,
    bool* connection_closed = nullptr,
    std::string* error = nullptr);

void transport_close(TransportSessionState* session);

bool transport_is_open(const TransportSessionState& session);

} // namespace madoka

#endif
