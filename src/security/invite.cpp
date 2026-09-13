#include "security/invite.hpp"

#include "platform/durability.hpp"
#include "platform/file_lock.hpp"
#include "platform/private_storage.hpp"
#include "platform/random.hpp"

#include <algorithm>
#include <openssl/evp.h>

namespace madoka {
namespace {

constexpr std::string_view invite_prefix = "madoka://invite/";
constexpr std::string_view peer_prefix = "madoka-peer-v1:";
constexpr std::size_t maximum_endpoint_size = 255;

bool valid_endpoint(std::string_view endpoint) {
    std::string address;
    uint16_t port = 0;
    return !endpoint.empty() && endpoint.size() <= maximum_endpoint_size &&
           endpoint.find('\0') == std::string_view::npos &&
           parse_endpoint(endpoint, &address, &port) && port != 0;
}

void append_u16(std::vector<uint8_t>& output, uint16_t value) {
    output.push_back(static_cast<uint8_t>(value >> 8));
    output.push_back(static_cast<uint8_t>(value));
}

void append_u64(std::vector<uint8_t>& output, uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        output.push_back(static_cast<uint8_t>(value >> shift));
    }
}

uint16_t read_u16(const uint8_t* data) {
    return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) |
                                 data[1]);
}

uint64_t read_u64(const uint8_t* data) {
    uint64_t result = 0;
    for (std::size_t index = 0; index < 8; ++index) {
        result = (result << 8) | data[index];
    }
    return result;
}

std::string base64url_encode(std::span<const uint8_t> input) {
    constexpr std::string_view alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string output;
    output.reserve((input.size() * 4 + 2) / 3);
    uint32_t buffer = 0;
    int bits = 0;
    for (const uint8_t byte : input) {
        buffer = (buffer << 8) | byte;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            output.push_back(alphabet[(buffer >> bits) & 63]);
        }
    }
    if (bits != 0) {
        output.push_back(alphabet[(buffer << (6 - bits)) & 63]);
    }
    return output;
}

bool base64url_decode(std::string_view input,
                      std::vector<uint8_t>* output,
                      std::string* error) {
    if (output == nullptr || input.empty() || input.size() % 4 == 1) {
        if (error != nullptr) {
            *error = "Invalid invitation encoding";
        }
        return false;
    }
    std::vector<uint8_t> decoded;
    decoded.reserve(input.size() * 3 / 4);
    uint32_t buffer = 0;
    int bits = 0;
    for (const char character : input) {
        uint8_t value = 0;
        if (character >= 'A' && character <= 'Z') {
            value = static_cast<uint8_t>(character - 'A');
        } else if (character >= 'a' && character <= 'z') {
            value = static_cast<uint8_t>(character - 'a' + 26);
        } else if (character >= '0' && character <= '9') {
            value = static_cast<uint8_t>(character - '0' + 52);
        } else if (character == '-') {
            value = 62;
        } else if (character == '_') {
            value = 63;
        } else {
            if (error != nullptr) {
                *error = "Invalid invitation encoding";
            }
            return false;
        }
        buffer = (buffer << 6) | value;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            decoded.push_back(static_cast<uint8_t>(buffer >> bits));
        }
    }
    if ((bits != 0 && (buffer & ((1U << bits) - 1U)) != 0) ||
        base64url_encode(decoded) != input) {
        if (error != nullptr) {
            *error = "Non-canonical invitation encoding";
        }
        return false;
    }
    *output = std::move(decoded);
    return true;
}

bool valid_identity_binding(const TrustedPeer& peer) {
    NodeId derived{};
    std::size_t size = derived.size();
    return peer.id != NodeId{} &&
           EVP_Q_digest(nullptr,
                        "SHA256",
                        nullptr,
                        peer.public_key.data(),
                        peer.public_key.size(),
                        derived.data(),
                        &size) == 1 &&
           size == derived.size() && derived == peer.id;
}

std::filesystem::path invite_path(const TrustState& state,
                                  const InviteTicket& ticket) {
    return state.directory / ("invite-" + hex(ticket.secret) + ".ticket");
}

std::filesystem::path peer_path(const TrustState& state, const NodeId& id) {
    return state.directory / ("peer-" + hex(id) + ".trust");
}

std::string encode_peer(const TrustedPeer& peer) {
    std::vector<uint8_t> bytes;
    bytes.reserve(1 + 32 + 32 + 2 + peer.endpoint.size());
    bytes.push_back(1);
    bytes.insert(bytes.end(), peer.id.begin(), peer.id.end());
    bytes.insert(bytes.end(), peer.public_key.begin(), peer.public_key.end());
    append_u16(bytes, static_cast<uint16_t>(peer.endpoint.size()));
    bytes.insert(bytes.end(), peer.endpoint.begin(), peer.endpoint.end());
    return std::string{peer_prefix} + base64url_encode(bytes) + "\n";
}

bool decode_peer(std::string_view text, TrustedPeer* peer, std::string* error) {
    if (peer == nullptr || !text.starts_with(peer_prefix) ||
        !text.ends_with('\n')) {
        if (error != nullptr) {
            *error = "Invalid trusted peer record";
        }
        return false;
    }
    text.remove_prefix(peer_prefix.size());
    text.remove_suffix(1);
    std::vector<uint8_t> bytes;
    if (!base64url_decode(text, &bytes, error) ||
        bytes.size() < 1 + 32 + 32 + 2 || bytes[0] != 1) {
        if (error != nullptr && error->empty()) {
            *error = "Invalid trusted peer record";
        }
        return false;
    }
    const uint16_t endpoint_size = read_u16(bytes.data() + 65);
    if (endpoint_size == 0 || endpoint_size > maximum_endpoint_size ||
        bytes.size() != 67 + static_cast<std::size_t>(endpoint_size)) {
        if (error != nullptr) {
            *error = "Invalid trusted peer endpoint";
        }
        return false;
    }
    TrustedPeer decoded{};
    std::copy_n(bytes.begin() + 1, decoded.id.size(), decoded.id.begin());
    std::copy_n(bytes.begin() + 33,
                decoded.public_key.size(),
                decoded.public_key.begin());
    decoded.endpoint.assign(reinterpret_cast<const char*>(bytes.data() + 67),
                            endpoint_size);
    if (!valid_identity_binding(decoded) || !valid_endpoint(decoded.endpoint)) {
        if (error != nullptr) {
            *error = "Invalid trusted peer identity or endpoint";
        }
        return false;
    }
    *peer = std::move(decoded);
    return true;
}

} // namespace

std::filesystem::path
trust_directory(const std::filesystem::path& identity_file) {
    auto result = identity_file;
    result += ".state";
    return result;
}

bool invite_generate(InviteTicket* ticket,
                     const NodeId& inviter_id,
                     std::string_view inviter_endpoint,
                     const IPv6& network,
                     uint64_t now_seconds,
                     uint64_t lifetime_seconds,
                     std::string* error) {
    if (ticket == nullptr || inviter_id == NodeId{} ||
        !valid_endpoint(inviter_endpoint) || now_seconds == 0 ||
        lifetime_seconds == 0 ||
        lifetime_seconds > MAX_INVITE_LIFETIME_SECONDS ||
        now_seconds > UINT64_MAX - lifetime_seconds) {
        if (error != nullptr) {
            *error = "Invalid invitation parameters";
        }
        return false;
    }
    if (network[0] != 0xfd ||
        !std::all_of(network.begin() + 8, network.end(), [](auto b) {
            return b == 0;
        })) {
        if (error != nullptr) {
            *error = "Network must be a locally assigned ULA /64";
        }
        return false;
    }
    InviteTicket generated{
        .network = network,
        .inviter_id = inviter_id,
        .inviter_endpoint = std::string{inviter_endpoint},
        .created_at = now_seconds,
        .expires_at = now_seconds + lifetime_seconds,
    };
    if (!platform::random_bytes(generated.secret, error)) {
        return false;
    }
    *ticket = std::move(generated);
    return true;
}

std::string invite_encode(const InviteTicket& ticket) {
    if (!valid_endpoint(ticket.inviter_endpoint) ||
        ticket.inviter_id == NodeId{} ||
        ticket.secret == decltype(ticket.secret){} || ticket.created_at == 0 ||
        ticket.expires_at <= ticket.created_at ||
        ticket.expires_at - ticket.created_at > MAX_INVITE_LIFETIME_SECONDS ||
        ticket.network[0] != 0xfd ||
        !std::all_of(
            ticket.network.begin() + 8, ticket.network.end(), [](auto b) {
                return b == 0;
            })) {
        return {};
    }
    std::vector<uint8_t> bytes;
    bytes.reserve(16 + 2 + ticket.inviter_endpoint.size() + 32 + 16 + 8 + 8);
    bytes.insert(bytes.end(), ticket.network.begin(), ticket.network.end());
    append_u16(bytes, static_cast<uint16_t>(ticket.inviter_endpoint.size()));
    bytes.insert(bytes.end(),
                 ticket.inviter_endpoint.begin(),
                 ticket.inviter_endpoint.end());
    bytes.insert(
        bytes.end(), ticket.inviter_id.begin(), ticket.inviter_id.end());
    bytes.insert(bytes.end(), ticket.secret.begin(), ticket.secret.end());
    append_u64(bytes, ticket.created_at);
    append_u64(bytes, ticket.expires_at);
    return std::string{invite_prefix} + base64url_encode(bytes);
}

bool invite_decode(std::string_view encoded,
                   InviteTicket* ticket,
                   std::string* error) {
    if (ticket == nullptr || !encoded.starts_with(invite_prefix) ||
        encoded.size() > 512) {
        if (error != nullptr) {
            *error = "Invalid invitation token";
        }
        return false;
    }
    encoded.remove_prefix(invite_prefix.size());
    std::vector<uint8_t> bytes;
    if (!base64url_decode(encoded, &bytes, error)) {
        return false;
    }
    if (bytes.size() < 16 + 2 + 32 + 16 + 8 + 8) {
        if (error != nullptr && error->empty()) {
            *error = "Unsupported invitation token";
        }
        return false;
    }
    InviteTicket decoded{};
    std::copy_n(bytes.begin(), 16, decoded.network.begin());
    if (decoded.network[0] != 0xfd || !std::all_of(decoded.network.begin() + 8,
                                                   decoded.network.end(),
                                                   [](auto b) {
                                                       return b == 0;
                                                   })) {
        if (error != nullptr) {
            *error = "Invalid network prefix in invitation";
        }
        return false;
    }

    const uint16_t endpoint_size = read_u16(bytes.data() + 16);
    const std::size_t expected_size = 16 + 2 + endpoint_size + 32 + 16 + 8 + 8;
    if (endpoint_size == 0 || endpoint_size > maximum_endpoint_size ||
        bytes.size() != expected_size) {
        if (error != nullptr) {
            *error = "Invalid invitation payload size";
        }
        return false;
    }
    std::size_t offset = 18;
    decoded.inviter_endpoint.assign(
        reinterpret_cast<const char*>(bytes.data() + offset), endpoint_size);
    offset += endpoint_size;
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                decoded.inviter_id.size(),
                decoded.inviter_id.begin());
    offset += decoded.inviter_id.size();
    std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                decoded.secret.size(),
                decoded.secret.begin());
    offset += decoded.secret.size();
    decoded.created_at = read_u64(bytes.data() + offset);
    offset += 8;
    decoded.expires_at = read_u64(bytes.data() + offset);

    if (!valid_endpoint(decoded.inviter_endpoint) ||
        decoded.inviter_id == NodeId{} ||
        decoded.secret == decltype(decoded.secret){} ||
        decoded.created_at == 0 || decoded.expires_at <= decoded.created_at ||
        decoded.expires_at - decoded.created_at > MAX_INVITE_LIFETIME_SECONDS) {
        if (error != nullptr) {
            *error = "Invalid invitation contents";
        }
        return false;
    }
    *ticket = std::move(decoded);
    return true;
}

bool invite_store(const TrustState& state,
                  const InviteTicket& ticket,
                  std::string* error) {
    const std::string token = invite_encode(ticket);
    if (token.empty() || state.directory.empty() ||
        !platform::private_ensure_directory(state.directory, error)) {
        return false;
    }
    std::intptr_t lock = platform::invalid_file_lock;
    if (!platform::file_lock_acquire(
            state.directory / "state.lock", &lock, error)) {
        return false;
    }
    const bool result = [&] {
        std::size_t active = 0;
        std::error_code iterator_error;
        for (std::filesystem::directory_iterator entries(state.directory,
                                                         iterator_error);
             !iterator_error &&
             entries != std::filesystem::directory_iterator{};
             entries.increment(iterator_error)) {
            const std::string filename = entries->path().filename().string();
            if (!filename.starts_with("invite-") ||
                !filename.ends_with(".ticket")) {
                continue;
            }
            std::string contents;
            InviteTicket existing{};
            if (!platform::private_read_file(
                    entries->path(), 513, &contents, error) ||
                !contents.ends_with('\n')) {
                return false;
            }
            contents.pop_back();
            if (!invite_decode(contents, &existing, error)) {
                return false;
            }
            if (existing.expires_at <= ticket.created_at) {
                std::error_code remove_error;
                std::filesystem::remove(entries->path(), remove_error);
                if (remove_error) {
                    if (error != nullptr) {
                        *error = "Cannot remove expired invitation";
                    }
                    return false;
                }
            } else {
                ++active;
            }
        }
        if (iterator_error) {
            if (error != nullptr) {
                *error =
                    "Cannot enumerate invitations: " + iterator_error.message();
            }
            return false;
        }
        if (active >= MAX_ACTIVE_INVITES) {
            if (error != nullptr) {
                *error = "Too many active invitations";
            }
            return false;
        }
        const auto path = invite_path(state, ticket);
        std::error_code exists_error;
        if (std::filesystem::exists(path, exists_error)) {
            if (error != nullptr) {
                *error = "Invitation collision; generate another invitation";
            }
            return false;
        }
        if (exists_error) {
            if (error != nullptr) {
                *error = "Cannot inspect invitation path";
            }
            return false;
        }
        return platform::private_write_atomically(path, token + "\n", error);
    }();
    platform::file_lock_release(&lock);
    return result;
}

bool invite_consume(const TrustState& state,
                    const InviteTicket& presented,
                    const NodeId& expected_inviter,
                    uint64_t now_seconds,
                    std::string* error) {
    if (presented.inviter_id != expected_inviter || presented.consumed) {
        if (error != nullptr) {
            *error = "Invitation was issued by another node";
        }
        return false;
    }
    std::intptr_t lock = platform::invalid_file_lock;
    if (!platform::file_lock_acquire(
            state.directory / "state.lock", &lock, error)) {
        return false;
    }
    const bool result = [&] {
        const auto path = invite_path(state, presented);
        std::string stored;
        if (!platform::private_read_file(path, 513, &stored, error)) {
            if (error != nullptr) {
                *error = "Invitation is unknown or was already used";
            }
            return false;
        }
        if (!stored.ends_with('\n')) {
            if (error != nullptr) {
                *error = "Stored invitation is malformed";
            }
            return false;
        }
        stored.pop_back();
        InviteTicket decoded{};
        if (!invite_decode(stored, &decoded, error) ||
            decoded.secret != presented.secret ||
            decoded.network != presented.network ||
            decoded.inviter_id != presented.inviter_id ||
            decoded.inviter_endpoint != presented.inviter_endpoint ||
            decoded.created_at != presented.created_at ||
            decoded.expires_at != presented.expires_at) {
            if (error != nullptr && error->empty()) {
                *error = "Invitation does not match the issued ticket";
            }
            return false;
        }

        std::error_code remove_error;
        const bool removed = std::filesystem::remove(path, remove_error);
        if (!removed || remove_error ||
            !platform::sync_parent_directory(path, error)) {
            if (error != nullptr && error->empty()) {
                *error = "Cannot consume invitation durably";
            }
            return false;
        }
        if (now_seconds < decoded.created_at ||
            now_seconds >= decoded.expires_at) {
            if (error != nullptr) {
                *error = "Invitation expired";
            }
            return false;
        }
        return true;
    }();
    platform::file_lock_release(&lock);
    return result;
}

bool trust_load(TrustState* state,
                const std::filesystem::path& identity_file,
                std::string* error) {
    if (state == nullptr || identity_file.empty()) {
        if (error != nullptr) {
            *error = "Invalid trust state";
        }
        return false;
    }
    TrustState loaded{.directory = trust_directory(identity_file)};
    if (!platform::private_ensure_directory(loaded.directory, error)) {
        return false;
    }
    std::error_code iterator_error;
    for (std::filesystem::directory_iterator entries(loaded.directory,
                                                     iterator_error);
         !iterator_error && entries != std::filesystem::directory_iterator{};
         entries.increment(iterator_error)) {
        const std::string filename = entries->path().filename().string();
        if (!filename.starts_with("peer-") || !filename.ends_with(".trust")) {
            continue;
        }
        std::string contents;
        TrustedPeer peer{};
        if (!platform::private_read_file(
                entries->path(), 1024, &contents, error) ||
            !decode_peer(contents, &peer, error) ||
            filename != "peer-" + hex(peer.id) + ".trust") {
            if (error != nullptr && error->empty()) {
                *error = "Invalid trusted peer filename";
            }
            return false;
        }
        if (std::find_if(loaded.peers.begin(),
                         loaded.peers.end(),
                         [&](const TrustedPeer& existing) {
                             return existing.id == peer.id;
                         }) != loaded.peers.end() ||
            loaded.peers.size() == MAX_TRUSTED_PEERS) {
            if (error != nullptr) {
                *error = "Duplicate or excessive trusted peer state";
            }
            return false;
        }
        loaded.peers.push_back(std::move(peer));
    }
    if (iterator_error) {
        if (error != nullptr) {
            *error =
                "Cannot enumerate trusted peers: " + iterator_error.message();
        }
        return false;
    }
    std::sort(loaded.peers.begin(),
              loaded.peers.end(),
              [](const TrustedPeer& left, const TrustedPeer& right) {
                  return left.id < right.id;
              });
    *state = std::move(loaded);
    return true;
}

bool trust_contains(const TrustState& state, const NodeId& id) noexcept {
    return trust_find(state, id) != nullptr;
}

const TrustedPeer* trust_find(const TrustState& state,
                              const NodeId& id) noexcept {
    const auto found =
        std::lower_bound(state.peers.begin(),
                         state.peers.end(),
                         id,
                         [](const TrustedPeer& peer, const NodeId& value) {
                             return peer.id < value;
                         });
    return found != state.peers.end() && found->id == id ? &*found : nullptr;
}

bool trust_address_available(const TrustState& state,
                             const IPv6& network,
                             const NodeId& local_id,
                             const NodeId& candidate_id) noexcept {
    if (candidate_id == NodeId{} || candidate_id == local_id) {
        return false;
    }
    const IPv6 candidate = virtual_address(network, candidate_id);
    if (candidate == virtual_address(network, local_id) ||
        std::all_of(candidate.begin() + 8, candidate.end(), [](uint8_t byte) {
            return byte == 0;
        })) {
        return false;
    }
    return std::none_of(
        state.peers.begin(), state.peers.end(), [&](const TrustedPeer& peer) {
            return peer.id != candidate_id &&
                   virtual_address(network, peer.id) == candidate;
        });
}

bool trust_add(TrustState* state, const TrustedPeer& peer, std::string* error) {
    if (state == nullptr || state->directory.empty() ||
        !valid_endpoint(peer.endpoint) || !valid_identity_binding(peer)) {
        if (error != nullptr) {
            *error = "Invalid trusted peer";
        }
        return false;
    }
    if (!platform::private_ensure_directory(state->directory, error)) {
        return false;
    }
    const auto found =
        std::lower_bound(state->peers.begin(),
                         state->peers.end(),
                         peer.id,
                         [](const TrustedPeer& existing, const NodeId& id) {
                             return existing.id < id;
                         });
    if (found == state->peers.end() &&
        state->peers.size() == MAX_TRUSTED_PEERS) {
        if (error != nullptr) {
            *error = "Trust table is full";
        }
        return false;
    }
    if (!platform::private_write_atomically(
            peer_path(*state, peer.id), encode_peer(peer), error)) {
        return false;
    }
    if (found != state->peers.end() && found->id == peer.id) {
        *found = peer;
    } else {
        state->peers.insert(found, peer);
    }
    return true;
}

} // namespace madoka
