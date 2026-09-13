#ifndef MADOKA_CRYPTO_TLS_HPP
#define MADOKA_CRYPTO_TLS_HPP

#include "core/config.hpp"
#include "platform/socket.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace madoka {

enum class TlsRole {
    Server,
    Client
};

struct TlsConfig {
    void* identity_key{nullptr};

    NodeId identity_id{};

    uint64_t generation{1};
};

struct TlsContext {
    void* native_ctx{nullptr};

    TlsRole role{TlsRole::Client};

    TlsConfig config{};
};

struct TlsSession {
    void* native_ssl{nullptr};

    SocketHandle socket{};

    NodeId peer_id{};

    std::array<uint8_t, 32> peer_pubkey{};

    bool established{false};
};

bool tls_context_init(TlsContext* ctx,
                      TlsRole role,
                      const TlsConfig& config,
                      std::string* error = nullptr);

bool tls_context_matches_identity(const TlsContext& ctx,
                                  const NodeId& identity_id,
                                  std::string* error = nullptr);

void tls_context_destroy(TlsContext* ctx);

bool tls_session_init(TlsSession* session,
                      TlsContext* ctx,
                      SocketHandle socket,
                      std::string* error = nullptr);

bool tls_handshake(
    TlsSession* session,
    std::optional<std::chrono::milliseconds> timeout = std::nullopt,
    std::string* error = nullptr);

int tls_send(TlsSession* session,
             const uint8_t* data,
             size_t size,
             std::string* error = nullptr);

int tls_receive(TlsSession* session,
                uint8_t* buffer,
                size_t size,
                bool* connection_closed = nullptr,
                std::string* error = nullptr);

void tls_close(TlsSession* session);

void tls_destroy(TlsSession* session);

bool tls_is_open(const TlsSession& session);

} // namespace madoka

#endif
