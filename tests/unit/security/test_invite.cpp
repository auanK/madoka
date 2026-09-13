#include "crypto/identity.hpp"
#include "security/invite.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <openssl/evp.h>

namespace {

std::filesystem::path temporary_root() {
    const auto nonce =
        std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() /
           ("madoka-invite-test-" + std::to_string(nonce));
}

void test_encoding_and_randomness() {
    madoka::IPv6 network{};
    network[0] = 0xfd;
    madoka::NodeId inviter{};
    inviter.fill(7);
    madoka::InviteTicket first{};
    madoka::InviteTicket second{};
    std::string error;
    assert(madoka::invite_generate(
        &first, inviter, "127.0.0.1:9001", network, 1000, 3600, &error));
    assert(madoka::invite_generate(
        &second, inviter, "127.0.0.1:9001", network, 1000, 3600, &error));
    assert(first.secret != second.secret);

    const std::string encoded = madoka::invite_encode(first);
    assert(encoded.starts_with("madoka://invite/"));
    assert(!encoded.starts_with("madoka://invite/v"));
    madoka::InviteTicket decoded{};
    assert(madoka::invite_decode(encoded, &decoded, &error));
    assert(decoded.network == first.network);
    assert(decoded.secret == first.secret);
    assert(decoded.inviter_id == first.inviter_id);
    assert(decoded.inviter_endpoint == first.inviter_endpoint);
    assert(decoded.created_at == first.created_at);
    assert(decoded.expires_at == first.expires_at);
    assert(
        !madoka::invite_decode("madoka://invite/not+base64", &decoded, &error));
    assert(!madoka::invite_generate(
        &decoded, inviter, "localhost:9001", network, 1000, 3600, &error));
    assert(!madoka::invite_generate(
        &decoded, inviter, "127.0.0.1:0", network, 1000, 3600, &error));
}

void test_address_collision() {
    madoka::IPv6 network{};
    network[0] = 0xfd;
    madoka::NodeId local{};
    local.fill(1);
    madoka::NodeId peer{};
    peer.fill(2);
    madoka::NodeId collision{};
    collision.fill(3);
    std::copy_n(peer.begin(), 8, collision.begin());
    madoka::TrustState state{};
    state.peers.push_back(madoka::TrustedPeer{.id = peer});
    assert(madoka::trust_address_available(state, network, local, peer));
    assert(!madoka::trust_address_available(state, network, local, collision));
    assert(!madoka::trust_address_available(state, network, local, local));
}

void test_single_use_and_expiration(const std::filesystem::path& root) {
    madoka::TrustState state{};
    std::string error;
    assert(madoka::trust_load(&state, root / "identity.pem", &error));
    madoka::IPv6 network{};
    network[0] = 0xfd;
    madoka::NodeId inviter{};
    inviter.fill(9);

    madoka::InviteTicket usable{};
    assert(madoka::invite_generate(
        &usable, inviter, "127.0.0.1:9001", network, 1000, 60, &error));
    assert(madoka::invite_store(state, usable, &error));
    assert(madoka::invite_consume(state, usable, inviter, 1050, &error));
    assert(!madoka::invite_consume(state, usable, inviter, 1050, &error));

    madoka::InviteTicket expired{};
    assert(madoka::invite_generate(
        &expired, inviter, "127.0.0.1:9001", network, 2000, 60, &error));
    assert(madoka::invite_store(state, expired, &error));
    assert(!madoka::invite_consume(state, expired, inviter, 2061, &error));
    assert(!madoka::invite_consume(state, expired, inviter, 2050, &error));
}

void test_trust_persists(const std::filesystem::path& root) {
    madoka::TrustState state{};
    std::string error;
    assert(madoka::trust_load(&state, root / "identity.pem", &error));

    madoka::Identity peer_identity{};
    assert(madoka::identity_generate(&peer_identity, &error));
    std::array<uint8_t, 32> public_key{};
    std::size_t size = public_key.size();
    assert(EVP_PKEY_get_raw_public_key(
               reinterpret_cast<EVP_PKEY*>(peer_identity.key),
               public_key.data(),
               &size) == 1);
    assert(madoka::trust_add(&state,
                             madoka::TrustedPeer{.id = peer_identity.id,
                                                 .public_key = public_key,
                                                 .endpoint = "127.0.0.1:9002"},
                             &error));
    assert(madoka::trust_contains(state, peer_identity.id));

    madoka::TrustState reloaded{};
    assert(madoka::trust_load(&reloaded, root / "identity.pem", &error));
    const auto* peer = madoka::trust_find(reloaded, peer_identity.id);
    assert(peer != nullptr);
    assert(peer->public_key == public_key);
    assert(peer->endpoint == "127.0.0.1:9002");
    madoka::identity_close(&peer_identity);
}

} // namespace

int main() {
    const auto root = temporary_root();
    std::filesystem::create_directories(root);
    test_encoding_and_randomness();
    test_address_collision();
    test_single_use_and_expiration(root);
    test_trust_persists(root);
    std::filesystem::remove_all(root);
    std::cout << "Invitation and persistent trust tests passed.\n";
    return 0;
}
