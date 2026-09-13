#include "network/kademlia.hpp"

#include <algorithm>
#include <bit>
#include <cstddef>

namespace madoka {

void kademlia_init(KademliaTable* table, const NodeId& local_id) {
    if (!table) {
        return;
    }
    table->local_id = local_id;
    kademlia_clear(*table);
}

std::array<uint8_t, 32> kademlia_distance(const NodeId& a,
                                          const NodeId& b) noexcept {
    std::array<uint8_t, 32> dist{};
    for (std::size_t i = 0; i < dist.size(); ++i) {
        dist[i] = a[i] ^ b[i];
    }
    return dist;
}

uint16_t kademlia_bucket_index(const NodeId& local,
                               const NodeId& remote) noexcept {
    for (std::size_t byte_idx = 0; byte_idx < local.size(); ++byte_idx) {
        const uint8_t xor_val = local[byte_idx] ^ remote[byte_idx];
        if (xor_val != 0) {
            const int clz = std::countl_zero(xor_val);
            return static_cast<uint16_t>(byte_idx * 8 +
                                         static_cast<std::size_t>(clz));
        }
    }
    return 256;
}

bool kademlia_insert(KademliaTable& table,
                     const NodeContact& contact,
                     std::function<bool(const NodeContact&)> ping_fn) {
    if (contact.id == table.local_id) {
        return false;
    }

    const uint16_t bucket_idx =
        kademlia_bucket_index(table.local_id, contact.id);
    if (bucket_idx >= KADEMLIA_BUCKETS) {
        return false;
    }

    auto& bucket = table.buckets[bucket_idx];

    auto it = std::find_if(bucket.contacts.begin(),
                           bucket.contacts.end(),
                           [&](const NodeContact& c) {
                               return c.id == contact.id;
                           });

    if (it != bucket.contacts.end()) {
        NodeContact updated = *it;
        updated.public_key = contact.public_key;
        updated.virtual_address = contact.virtual_address;
        if (!contact.endpoint.empty()) {
            updated.endpoint = contact.endpoint;
        }
        updated.last_seen_ms = contact.last_seen_ms;
        updated.rtt_ms = contact.rtt_ms;
        updated.failed_pings = 0;

        bucket.contacts.erase(it);
        bucket.contacts.push_back(updated);
        return true;
    }

    if (bucket.contacts.size() < KADEMLIA_K) {
        bucket.contacts.push_back(contact);
        return true;
    }

    if (ping_fn != nullptr) {
        const NodeContact oldest = bucket.contacts.front();
        if (ping_fn(oldest)) {
            bucket.contacts.erase(bucket.contacts.begin());
            bucket.contacts.push_back(oldest);
            return false;
        }

        bucket.contacts.erase(bucket.contacts.begin());
        bucket.contacts.push_back(contact);
        return true;
    }

    return false;
}

std::vector<NodeContact> kademlia_find_closest(const KademliaTable& table,
                                               const NodeId& target,
                                               std::size_t count) {
    std::vector<NodeContact> all;
    for (const auto& bucket : table.buckets) {
        for (const auto& contact : bucket.contacts) {
            all.push_back(contact);
        }
    }

    auto distance_cmp = [&](const NodeContact& a, const NodeContact& b) {
        for (std::size_t i = 0; i < 32; ++i) {
            const uint8_t da = a.id[i] ^ target[i];
            const uint8_t db = b.id[i] ^ target[i];
            if (da != db) {
                return da < db;
            }
        }
        return false;
    };

    if (all.size() > count) {
        std::partial_sort(all.begin(),
                          all.begin() + static_cast<std::ptrdiff_t>(count),
                          all.end(),
                          distance_cmp);
        all.resize(count);
    } else {
        std::sort(all.begin(), all.end(), distance_cmp);
    }

    return all;
}

bool kademlia_remove(KademliaTable& table, const NodeId& id) {
    const uint16_t bucket_idx = kademlia_bucket_index(table.local_id, id);
    if (bucket_idx >= KADEMLIA_BUCKETS) {
        return false;
    }

    auto& bucket = table.buckets[bucket_idx];
    auto it = std::find_if(bucket.contacts.begin(),
                           bucket.contacts.end(),
                           [&](const NodeContact& c) {
                               return c.id == id;
                           });

    if (it != bucket.contacts.end()) {
        bucket.contacts.erase(it);
        return true;
    }
    return false;
}

const NodeContact* kademlia_find(const KademliaTable& table, const NodeId& id) {
    const uint16_t bucket_idx = kademlia_bucket_index(table.local_id, id);
    if (bucket_idx >= KADEMLIA_BUCKETS) {
        return nullptr;
    }

    const auto& bucket = table.buckets[bucket_idx];
    for (const auto& contact : bucket.contacts) {
        if (contact.id == id) {
            return &contact;
        }
    }
    return nullptr;
}

std::size_t kademlia_total_contacts(const KademliaTable& table) noexcept {
    std::size_t total = 0;
    for (const auto& bucket : table.buckets) {
        total += bucket.contacts.size();
    }
    return total;
}

void kademlia_clear(KademliaTable& table) noexcept {
    for (auto& bucket : table.buckets) {
        bucket.contacts.clear();
    }
}

} // namespace madoka
