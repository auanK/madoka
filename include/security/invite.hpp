#ifndef MADOKA_SECURITY_INVITE_HPP
#define MADOKA_SECURITY_INVITE_HPP

#include "core/config.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace madoka {

inline constexpr uint64_t DEFAULT_INVITE_LIFETIME_SECONDS = 3600;
inline constexpr uint64_t MAX_INVITE_LIFETIME_SECONDS = 86400;
inline constexpr std::size_t MAX_TRUSTED_PEERS = 15;
inline constexpr std::size_t MAX_ACTIVE_INVITES = 64;

struct InviteTicket {
    IPv6 network{};
    std::array<uint8_t, 16> secret{};
    NodeId inviter_id{};
    std::string inviter_endpoint{};
    uint64_t created_at{0};
    uint64_t expires_at{0};
    bool consumed{false};
};

struct TrustedPeer {
    NodeId id{};
    std::array<uint8_t, 32> public_key{};
    std::string endpoint{};
};

struct TrustState {
    std::filesystem::path directory{};
    std::vector<TrustedPeer> peers{};
};

std::filesystem::path
trust_directory(const std::filesystem::path& identity_file);

bool invite_generate(
    InviteTicket* ticket,
    const NodeId& inviter_id,
    std::string_view inviter_endpoint,
    const IPv6& network,
    uint64_t now_seconds,
    uint64_t lifetime_seconds = DEFAULT_INVITE_LIFETIME_SECONDS,
    std::string* error = nullptr);

std::string invite_encode(const InviteTicket& ticket);

bool invite_decode(std::string_view encoded,
                   InviteTicket* ticket,
                   std::string* error = nullptr);

bool invite_store(const TrustState& state,
                  const InviteTicket& ticket,
                  std::string* error = nullptr);

bool invite_consume(const TrustState& state,
                    const InviteTicket& presented,
                    const NodeId& expected_inviter,
                    uint64_t now_seconds,
                    std::string* error = nullptr);

bool trust_load(TrustState* state,
                const std::filesystem::path& identity_file,
                std::string* error = nullptr);

bool trust_contains(const TrustState& state, const NodeId& id) noexcept;

const TrustedPeer* trust_find(const TrustState& state,
                              const NodeId& id) noexcept;

bool trust_address_available(const TrustState& state,
                             const IPv6& network,
                             const NodeId& local_id,
                             const NodeId& candidate_id) noexcept;

bool trust_add(TrustState* state,
               const TrustedPeer& peer,
               std::string* error = nullptr);

} // namespace madoka

#endif
