#include "crypto/tls.hpp"

#include <algorithm>
#include <cstring>
#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string>

#if !defined(_WIN32)
#include <csignal>
#endif

namespace madoka {

namespace {

#if !defined(_WIN32)
struct PosixTlsInit {
    PosixTlsInit() {
        std::signal(SIGPIPE, SIG_IGN);
    }
};
static PosixTlsInit posix_tls_init;
#endif

std::string get_openssl_errors() {
    std::string result;
    unsigned long err = 0;
    char buf[256];
    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, buf, sizeof(buf));
        if (!result.empty()) {
            result += " | ";
        }
        result += buf;
    }
    return result.empty() ? "No OpenSSL error details available" : result;
}

int verify_self_signed_peer(int, X509_STORE_CTX* store) {
    X509* certificate = X509_STORE_CTX_get_current_cert(store);
    const int not_before =
        certificate != nullptr
            ? X509_cmp_current_time(X509_get0_notBefore(certificate))
            : 0;
    const int not_after =
        certificate != nullptr
            ? X509_cmp_current_time(X509_get0_notAfter(certificate))
            : 0;
    if (certificate == nullptr || X509_STORE_CTX_get_error_depth(store) != 0 ||
        not_before >= 0 || not_after <= 0 ||
        X509_NAME_cmp(X509_get_subject_name(certificate),
                      X509_get_issuer_name(certificate)) != 0) {
        return 0;
    }
    EVP_PKEY* key = X509_get0_pubkey(certificate);
    if (key == nullptr || !EVP_PKEY_is_a(key, "ED25519") ||
        X509_verify(certificate, key) != 1) {
        return 0;
    }
    X509_STORE_CTX_set_error(store, X509_V_OK);
    return 1;
}

std::unique_ptr<X509, decltype(&X509_free)>
make_self_signed_certificate(const TlsConfig& config, std::string* error) {
    auto* key = reinterpret_cast<EVP_PKEY*>(config.identity_key);
    std::unique_ptr<X509, decltype(&X509_free)> certificate(X509_new(),
                                                            X509_free);
    if (key == nullptr || !EVP_PKEY_is_a(key, "ED25519") || !certificate ||
        X509_set_version(certificate.get(), 2) != 1 ||
        ASN1_INTEGER_set_uint64(X509_get_serialNumber(certificate.get()),
                                config.generation) != 1 ||
        X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -60) ==
            nullptr ||
        X509_gmtime_adj(X509_getm_notAfter(certificate.get()),
                        3650L * 24L * 60L * 60L) == nullptr ||
        X509_set_pubkey(certificate.get(), key) != 1) {
        if (error != nullptr) {
            *error = "Cannot create in-memory Ed25519 certificate: " +
                     get_openssl_errors();
        }
        return {nullptr, X509_free};
    }
    X509_NAME* subject = X509_get_subject_name(certificate.get());
    const std::string common_name = hex(config.identity_id);
    if (subject == nullptr ||
        X509_NAME_add_entry_by_txt(
            subject,
            "CN",
            MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(common_name.data()),
            static_cast<int>(common_name.size()),
            -1,
            0) != 1 ||
        X509_set_issuer_name(certificate.get(), subject) != 1 ||
        X509_sign(certificate.get(), key, nullptr) <= 0) {
        if (error != nullptr) {
            *error = "Cannot sign in-memory Ed25519 certificate: " +
                     get_openssl_errors();
        }
        return {nullptr, X509_free};
    }
    return certificate;
}

} // namespace

bool tls_context_init(TlsContext* ctx,
                      TlsRole role,
                      const TlsConfig& config,
                      std::string* error) {
    if (!ctx) {
        if (error)
            *error = "TlsContext pointer is null";
        return false;
    }
    tls_context_destroy(ctx);

    const SSL_METHOD* method =
        (role == TlsRole::Server) ? TLS_server_method() : TLS_client_method();
    SSL_CTX* ssl_ctx = SSL_CTX_new(method);
    if (!ssl_ctx) {
        if (error)
            *error = "Failed to allocate SSL_CTX: " + get_openssl_errors();
        return false;
    }

    if (SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION) != 1) {
        if (error)
            *error = "Failed to enforce TLS 1.3: " + get_openssl_errors();
        SSL_CTX_free(ssl_ctx);
        return false;
    }

    auto certificate = make_self_signed_certificate(config, error);
    auto* key = reinterpret_cast<EVP_PKEY*>(config.identity_key);
    if (!certificate ||
        SSL_CTX_use_certificate(ssl_ctx, certificate.get()) != 1 ||
        SSL_CTX_use_PrivateKey(ssl_ctx, key) != 1 ||
        SSL_CTX_check_private_key(ssl_ctx) != 1) {
        if (error != nullptr && error->empty()) {
            *error = "Cannot configure in-memory Ed25519 certificate: " +
                     get_openssl_errors();
        }
        SSL_CTX_free(ssl_ctx);
        return false;
    }

    SSL_CTX_set_verify(ssl_ctx,
                       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       verify_self_signed_peer);
    SSL_CTX_set_verify_depth(ssl_ctx, 0);

    ctx->native_ctx = ssl_ctx;
    ctx->role = role;
    ctx->config = config;
    return true;
}

void tls_context_destroy(TlsContext* ctx) {
    if (!ctx)
        return;
    if (ctx->native_ctx) {
        SSL_CTX_free(reinterpret_cast<SSL_CTX*>(ctx->native_ctx));
        ctx->native_ctx = nullptr;
    }
}

bool tls_context_matches_identity(const TlsContext& ctx,
                                  const NodeId& identity_id,
                                  std::string* error) {
    if (!ctx.native_ctx) {
        if (error)
            *error = "TLS context is not initialized";
        return false;
    }

    X509* cert =
        SSL_CTX_get0_certificate(reinterpret_cast<SSL_CTX*>(ctx.native_ctx));
    EVP_PKEY* public_key = cert ? X509_get0_pubkey(cert) : nullptr;
    if (!public_key || !EVP_PKEY_is_a(public_key, "ED25519")) {
        if (error)
            *error = "Local TLS certificate must contain an Ed25519 key";
        return false;
    }

    std::array<uint8_t, 32> raw_public_key{};
    std::size_t raw_size = raw_public_key.size();
    if (EVP_PKEY_get_raw_public_key(
            public_key, raw_public_key.data(), &raw_size) != 1 ||
        raw_size != raw_public_key.size()) {
        if (error)
            *error = "Failed to export local TLS Ed25519 public key";
        return false;
    }

    NodeId derived_id{};
    std::size_t digest_size = derived_id.size();
    if (EVP_Q_digest(nullptr,
                     "SHA256",
                     nullptr,
                     raw_public_key.data(),
                     raw_public_key.size(),
                     derived_id.data(),
                     &digest_size) != 1 ||
        digest_size != derived_id.size()) {
        if (error)
            *error = "Failed to derive Node ID from local TLS certificate";
        return false;
    }

    if (derived_id != identity_id) {
        if (error)
            *error = "Local TLS certificate public key does not match identity";
        return false;
    }
    return true;
}

bool tls_session_init(TlsSession* session,
                      TlsContext* ctx,
                      SocketHandle socket,
                      std::string* error) {
    if (!session) {
        if (error)
            *error = "TlsSession pointer is null";
        return false;
    }
    tls_destroy(session);

    if (!ctx || !ctx->native_ctx) {
        if (error)
            *error = "Invalid or uninitialized TlsContext";
        return false;
    }

    auto* ssl_ctx = reinterpret_cast<SSL_CTX*>(ctx->native_ctx);
    SSL* ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        if (error)
            *error = "Failed to instantiate SSL: " + get_openssl_errors();
        return false;
    }

    if (SSL_set_fd(ssl, static_cast<int>(socket.fd)) != 1) {
        if (error)
            *error =
                "Failed to associate socket with SSL: " + get_openssl_errors();
        SSL_free(ssl);
        return false;
    }

    session->native_ssl = ssl;
    session->socket = socket;
    session->peer_id.fill(0);
    session->peer_pubkey.fill(0);
    session->established = false;
    return true;
}

bool tls_handshake(TlsSession* session,
                   std::optional<std::chrono::milliseconds> timeout,
                   std::string* error) {
    if (!session || !session->native_ssl) {
        if (error)
            *error = "TLS session is not initialized";
        return false;
    }

    auto* ssl = reinterpret_cast<SSL*>(session->native_ssl);

    if (timeout.has_value()) {
        socket_set_timeout(&session->socket, *timeout, true, true);
    }

    int res = SSL_is_server(ssl) ? SSL_accept(ssl) : SSL_connect(ssl);
    if (res <= 0) {
        int err = SSL_get_error(ssl, res);
        std::string details = get_openssl_errors();
        if (details.empty()) {
            details = "SSL error code " + std::to_string(err);
        }
        if (error)
            *error = "TLS handshake failed: " + details;
        tls_close(session);
        return false;
    }

    X509* peer_cert = SSL_get1_peer_certificate(ssl);
    if (!peer_cert) {
        if (error)
            *error = "Mutual TLS required: peer failed to present an X.509 "
                     "certificate";
        tls_close(session);
        return false;
    }
    std::unique_ptr<X509, decltype(&X509_free)> cert_guard(peer_cert,
                                                           X509_free);

    long verify_result = SSL_get_verify_result(ssl);
    if (verify_result != X509_V_OK) {
        if (error)
            *error = "Peer certificate verification failed: " +
                     std::string(X509_verify_cert_error_string(verify_result));
        tls_close(session);
        return false;
    }

    EVP_PKEY* pubkey = X509_get0_pubkey(peer_cert);
    if (!pubkey) {
        if (error)
            *error = "Failed to extract public key from peer certificate";
        tls_close(session);
        return false;
    }

    if (!EVP_PKEY_is_a(pubkey, "ED25519")) {
        if (error)
            *error = "Peer certificate public key algorithm is not Ed25519";
        tls_close(session);
        return false;
    }

    std::array<uint8_t, 32> raw_pub{};
    std::size_t raw_pub_len = raw_pub.size();
    if (EVP_PKEY_get_raw_public_key(pubkey, raw_pub.data(), &raw_pub_len) !=
            1 ||
        raw_pub_len != 32) {
        if (error)
            *error = "Failed to extract 32-byte raw Ed25519 public key from "
                     "peer certificate";
        tls_close(session);
        return false;
    }

    NodeId id{};
    std::size_t id_len = id.size();
    if (EVP_Q_digest(nullptr,
                     "SHA256",
                     nullptr,
                     raw_pub.data(),
                     raw_pub.size(),
                     id.data(),
                     &id_len) != 1 ||
        id_len != id.size()) {
        if (error)
            *error = "Failed to calculate SHA-256 Node ID from peer public key";
        tls_close(session);
        return false;
    }

    session->peer_id = id;
    session->peer_pubkey = raw_pub;
    session->established = true;
    return true;
}

int tls_send(TlsSession* session,
             const uint8_t* data,
             size_t size,
             std::string* error) {
    if (!session || !session->native_ssl || !session->established) {
        if (error)
            *error = "Cannot send data: TLS session not established";
        return -1;
    }

    auto* ssl = reinterpret_cast<SSL*>(session->native_ssl);
    size_t total_written = 0;
    while (total_written < size) {
        const auto remaining = static_cast<int>(size - total_written);
        const char* buf = reinterpret_cast<const char*>(data + total_written);

        int written = SSL_write(ssl, buf, remaining);
        if (written <= 0) {
            int err = SSL_get_error(ssl, written);
            if (error)
                *error = "SSL_write failed (code " + std::to_string(err) +
                         "): " + get_openssl_errors();
            tls_close(session);
            return -1;
        }
        total_written += static_cast<size_t>(written);
    }
    return static_cast<int>(total_written);
}

int tls_receive(TlsSession* session,
                uint8_t* buffer,
                size_t size,
                bool* connection_closed,
                std::string* error) {
    if (connection_closed)
        *connection_closed = false;
    if (!session || !session->native_ssl || !session->established) {
        if (error)
            *error = "Cannot receive data: TLS session not established";
        return -1;
    }
    if (size == 0)
        return 0;

    auto* ssl = reinterpret_cast<SSL*>(session->native_ssl);
    int bytes_read = SSL_read(ssl, buffer, static_cast<int>(size));
    if (bytes_read <= 0) {
        int err = SSL_get_error(ssl, bytes_read);
        if (err == SSL_ERROR_ZERO_RETURN) {
            if (connection_closed)
                *connection_closed = true;
            tls_close(session);
            return 0;
        }
        if (err == SSL_ERROR_SYSCALL) {
            if (socket_is_timeout_error()) {
                if (error)
                    *error = "TLS read timed out via socket timeout";
                return -1;
            } else {
                if (error)
                    *error =
                        "TLS socket read error: " + socket_last_error_text();
            }
            tls_close(session);
            return -1;
        }
        if (error)
            *error = "SSL_read failed (code " + std::to_string(err) +
                     "): " + get_openssl_errors();
        tls_close(session);
        return -1;
    }
    return bytes_read;
}

void tls_close(TlsSession* session) {
    if (!session)
        return;
    if (session->native_ssl) {
        auto* ssl = reinterpret_cast<SSL*>(session->native_ssl);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        session->native_ssl = nullptr;
    }
    session->established = false;
}

void tls_destroy(TlsSession* session) {
    if (!session)
        return;
    tls_close(session);
    socket_close(&session->socket);
}

bool tls_is_open(const TlsSession& session) {
    return session.native_ssl != nullptr && session.established &&
           socket_is_valid(session.socket);
}

} // namespace madoka
