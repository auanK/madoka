#include "transport/session.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>

namespace madoka {

namespace {

std::string to_hex_str(std::span<const uint8_t> bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string s;
    s.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        s.push_back(digits[(b >> 4) & 0x0F]);
        s.push_back(digits[b & 0x0F]);
    }
    return s;
}

} // namespace

bool transport_server_init(TransportServerState* server,
                           uint16_t port,
                           std::string_view bind_address,
                           std::string*) {
    if (!server)
        return false;
    transport_server_close(server);

    server->is_tls = false;
    server->bind_address = std::string(bind_address);
    server->port = port;
    server->peer_validator = nullptr;
    server->is_listening = false;
    return true;
}

bool transport_server_init_tls(
    TransportServerState* server,
    const TlsConfig& config,
    uint16_t port,
    std::string_view bind_address,
    std::function<bool(const NodeId&)> peer_validator,
    std::string* error) {
    if (!server)
        return false;
    transport_server_close(server);

    if (!tls_context_init(&server->tls_ctx, TlsRole::Server, config, error)) {
        return false;
    }

    server->is_tls = true;
    server->bind_address = std::string(bind_address);
    server->port = port;
    server->peer_validator = std::move(peer_validator);
    server->is_listening = false;
    return true;
}

bool transport_server_start(TransportServerState* server, std::string* error) {
    if (!server)
        return false;
    server->is_listening = false;
    socket_close(&server->listen_socket);

    const bool is_ipv4 = socket_is_ipv4_address(server->bind_address);
    server->listen_socket = socket_create_tcp(is_ipv4 ? AF_INET : AF_INET6);
    if (!socket_is_valid(server->listen_socket)) {
        if (error)
            *error = "Failed to create socket: " + socket_last_error_text();
        return false;
    }

    socket_set_reuse_addr(&server->listen_socket);
    if (!is_ipv4) {
        bool v6only = (server->bind_address != "::");
        socket_set_ipv6_only(&server->listen_socket, v6only);
    }

    if (!socket_bind(&server->listen_socket,
                     server->bind_address,
                     server->port,
                     error)) {
        socket_close(&server->listen_socket);
        return false;
    }

    if (!socket_listen(&server->listen_socket, 128, error)) {
        socket_close(&server->listen_socket);
        return false;
    }

    server->is_listening = true;
    return true;
}

void transport_server_close(TransportServerState* server) {
    if (!server)
        return;
    socket_close(&server->listen_socket);
    if (server->is_tls) {
        tls_context_destroy(&server->tls_ctx);
    }
    server->is_listening = false;
}

uint16_t transport_server_local_port(const TransportServerState& server) {
    return socket_get_local_port(server.listen_socket);
}

bool transport_accept(TransportServerState* server,
                      TransportSessionState* out_session,
                      std::optional<std::chrono::milliseconds> timeout,
                      std::string* error) {
    if (!server || !server->is_listening) {
        if (error)
            *error = "Server is not listening";
        return false;
    }
    if (!out_session)
        return false;
    transport_close(out_session);

    std::string remote_endpoint;
    SocketHandle client_sock =
        socket_accept(&server->listen_socket,
                      &remote_endpoint,
                      timeout.value_or(std::chrono::milliseconds{0}),
                      error);
    if (!socket_is_valid(client_sock)) {
        return false;
    }

    out_session->socket = client_sock;
    out_session->remote_endpoint = remote_endpoint;
    out_session->recv_buffer.reserve(RECV_CHUNK_SIZE * 2);
    out_session->is_tls = server->is_tls;

    if (server->is_tls) {
        if (!tls_session_init(
                &out_session->tls, &server->tls_ctx, client_sock, error)) {
            socket_close(&client_sock);
            out_session->socket = SocketHandle{};
            return false;
        }

        if (!tls_handshake(&out_session->tls, timeout, error)) {
            tls_destroy(&out_session->tls);
            out_session->socket = SocketHandle{};
            return false;
        }

        out_session->peer_node_id = out_session->tls.peer_id;

        if (server->peer_validator &&
            !server->peer_validator(*out_session->peer_node_id)) {
            if (error)
                *error = "Peer rejected by authorization policy: " +
                         to_hex_str(*out_session->peer_node_id);
            tls_destroy(&out_session->tls);
            out_session->socket = SocketHandle{};
            return false;
        }
    }

    out_session->is_open = true;
    return true;
}

bool transport_connect(TransportSessionState* session,
                       std::string_view host,
                       uint16_t port,
                       std::chrono::milliseconds timeout,
                       std::string* error) {
    if (!session)
        return false;
    transport_close(session);

    SocketHandle sock = socket_connect(host, port, timeout, error);
    if (!socket_is_valid(sock)) {
        return false;
    }

    session->socket = sock;
    session->is_tls = false;
    session->remote_endpoint = format_endpoint(host, port);
    session->peer_node_id = std::nullopt;
    session->recv_buffer.reserve(RECV_CHUNK_SIZE * 2);
    session->is_open = true;
    return true;
}

bool transport_connect_tls(TransportSessionState* session,
                           const TlsConfig& client_tls_config,
                           std::string_view host,
                           uint16_t port,
                           std::optional<NodeId> expected_peer_id,
                           std::chrono::milliseconds timeout,
                           std::string* error) {
    if (!session)
        return false;
    transport_close(session);

    SocketHandle sock = socket_connect(host, port, timeout, error);
    if (!socket_is_valid(sock)) {
        return false;
    }

    TlsContext client_ctx{};
    if (!tls_context_init(
            &client_ctx, TlsRole::Client, client_tls_config, error)) {
        socket_close(&sock);
        return false;
    }

    if (!tls_session_init(&session->tls, &client_ctx, sock, error)) {
        tls_context_destroy(&client_ctx);
        socket_close(&sock);
        return false;
    }
    session->socket = sock;

    if (!tls_handshake(&session->tls, timeout, error)) {
        tls_destroy(&session->tls);
        tls_context_destroy(&client_ctx);
        session->socket = SocketHandle{};
        return false;
    }

    session->peer_node_id = session->tls.peer_id;

    if (expected_peer_id.has_value() &&
        *session->peer_node_id != *expected_peer_id) {
        if (error) {
            *error = "Peer Node ID mismatch: expected " +
                     to_hex_str(*expected_peer_id) + " but peer presented " +
                     to_hex_str(*session->peer_node_id);
        }
        tls_destroy(&session->tls);
        tls_context_destroy(&client_ctx);
        session->socket = SocketHandle{};
        return false;
    }

    tls_context_destroy(&client_ctx);

    session->is_tls = true;
    session->remote_endpoint = format_endpoint(host, port);
    session->recv_buffer.reserve(RECV_CHUNK_SIZE * 2);
    session->is_open = true;
    return true;
}

bool transport_send(TransportSessionState* session,
                    const Message& message,
                    std::string* error) {
    if (!session || !session->is_open.load(std::memory_order_acquire)) {
        if (error)
            *error = "Transport session is closed";
        return false;
    }

    std::vector<uint8_t> encoded = message_encode(message, error);
    if (encoded.empty()) {
        return false;
    }

    if (session->is_tls) {
        int sent =
            tls_send(&session->tls, encoded.data(), encoded.size(), error);
        if (sent < 0) {
            transport_close(session);
            return false;
        }
        return true;
    }

    size_t total_sent = 0;
    while (total_sent < encoded.size()) {
        int sent = socket_send(&session->socket,
                               encoded.data() + total_sent,
                               encoded.size() - total_sent,
                               error);
        if (sent <= 0) {
            transport_close(session);
            return false;
        }
        total_sent += static_cast<size_t>(sent);
    }
    return true;
}

bool transport_receive(TransportSessionState* session,
                       Message* out_message,
                       std::optional<std::chrono::milliseconds> timeout,
                       bool* connection_closed,
                       std::string* error) {
    if (connection_closed)
        *connection_closed = false;
    if (!session || !session->is_open.load(std::memory_order_acquire)) {
        if (error)
            *error = "Transport session is closed";
        return false;
    }

    if (timeout.has_value()) {
        socket_set_timeout(&session->socket, *timeout, true, false);
    }

    while (true) {
        if (session->recv_buffer.size() >= HEADER_SIZE) {
            std::optional<std::size_t> peek_size =
                message_peek_size(session->recv_buffer, error);
            if (!peek_size.has_value() && error && !error->empty()) {
                transport_close(session);
                return false;
            }

            if (peek_size.has_value()) {
                const std::size_t expected_total = *peek_size;
                if (expected_total > MAX_MESSAGE_SIZE) {
                    if (error) {
                        *error = "Message declared size (" +
                                 std::to_string(expected_total) +
                                 ") exceeds limit of " +
                                 std::to_string(MAX_MESSAGE_SIZE) + " bytes";
                    }
                    transport_close(session);
                    return false;
                }

                if (session->recv_buffer.size() >= expected_total) {
                    std::span<const uint8_t> slice(session->recv_buffer.data(),
                                                   expected_total);
                    if (!message_decode(slice, out_message, error)) {
                        transport_close(session);
                        return false;
                    }
                    session->recv_buffer.erase(
                        session->recv_buffer.begin(),
                        session->recv_buffer.begin() +
                            static_cast<std::ptrdiff_t>(expected_total));
                    return true;
                }
            }
        }

        if (session->recv_buffer.size() >= MAX_RECV_BUFFER_SIZE) {
            if (error) {
                *error = "Receive buffer exceeded contract limit of " +
                         std::to_string(MAX_RECV_BUFFER_SIZE) + " bytes";
            }
            transport_close(session);
            return false;
        }

        const std::size_t space_left =
            MAX_RECV_BUFFER_SIZE - session->recv_buffer.size();
        const std::size_t to_read = std::min(space_left, RECV_CHUNK_SIZE);
        std::array<uint8_t, RECV_CHUNK_SIZE> chunk{};
        int bytes_read = 0;

        if (session->is_tls) {
            bool peer_closed = false;
            bytes_read = tls_receive(
                &session->tls, chunk.data(), to_read, &peer_closed, error);
            if (bytes_read == 0 && peer_closed) {
                transport_close(session);
                if (connection_closed)
                    *connection_closed = true;
                if (!session->recv_buffer.empty() && error) {
                    *error = "Connection closed cleanly by peer with "
                             "incomplete message in buffer";
                }
                return false;
            }
            if (bytes_read < 0) {
                if (socket_is_timeout_error()) {
                    if (error)
                        error->clear();
                    return false;
                }
                transport_close(session);
                return false;
            }
        } else {
            bytes_read =
                socket_recv(&session->socket, chunk.data(), to_read, error);
            if (bytes_read == 0) {
                transport_close(session);
                if (connection_closed)
                    *connection_closed = true;
                if (!session->recv_buffer.empty() && error) {
                    *error = "Connection closed cleanly by peer with "
                             "incomplete message in buffer";
                }
                return false;
            }
            if (bytes_read < 0) {
                if (socket_is_timeout_error()) {
                    if (error)
                        error->clear();
                    return false;
                }
                transport_close(session);
                return false;
            }
        }

        session->recv_buffer.insert(session->recv_buffer.end(),
                                    chunk.begin(),
                                    chunk.begin() + bytes_read);
    }
}

void transport_close(TransportSessionState* session) {
    if (!session)
        return;
    session->is_open.store(false, std::memory_order_release);
    if (session->is_tls) {
        tls_destroy(&session->tls);
    } else {
        socket_close(&session->socket);
    }
    session->recv_buffer.clear();
}

bool transport_is_open(const TransportSessionState& session) {
    return session.is_open.load(std::memory_order_acquire);
}

} // namespace madoka
