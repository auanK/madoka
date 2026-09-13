#ifndef MADOKA_NETWORK_KADEMLIA_HPP
#define MADOKA_NETWORK_KADEMLIA_HPP

#include "core/config.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace madoka {

constexpr std::size_t KADEMLIA_K = 20;

constexpr std::size_t KADEMLIA_BUCKETS = 256;

struct NodeContact {
    NodeId id{};

    std::array<uint8_t, 32> public_key{};

    IPv6 virtual_address{};

    std::string endpoint{};

    uint64_t last_seen_ms{0};

    uint32_t rtt_ms{0};

    uint8_t failed_pings{0};

    bool operator==(const NodeContact& other) const = default;
};

struct KBucket {
    std::vector<NodeContact> contacts{};
};

struct KademliaTable {
    NodeId local_id{};
    std::array<KBucket, KADEMLIA_BUCKETS> buckets{};
};

void kademlia_init(KademliaTable* table, const NodeId& local_id);

[[nodiscard]] std::array<uint8_t, 32>
kademlia_distance(const NodeId& a, const NodeId& b) noexcept;

[[nodiscard]] uint16_t kademlia_bucket_index(const NodeId& local,
                                             const NodeId& remote) noexcept;

bool kademlia_insert(KademliaTable& table,
                     const NodeContact& contact,
                     std::function<bool(const NodeContact&)> ping_fn = nullptr);

[[nodiscard]] std::vector<NodeContact> kademlia_find_closest(
    const KademliaTable& table, const NodeId& target, std::size_t count);

bool kademlia_remove(KademliaTable& table, const NodeId& id);

[[nodiscard]] const NodeContact* kademlia_find(const KademliaTable& table,
                                               const NodeId& id);

[[nodiscard]] std::size_t
kademlia_total_contacts(const KademliaTable& table) noexcept;

void kademlia_clear(KademliaTable& table) noexcept;

} // namespace madoka

#endif
