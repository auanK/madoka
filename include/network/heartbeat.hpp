#ifndef MADOKA_NETWORK_HEARTBEAT_HPP
#define MADOKA_NETWORK_HEARTBEAT_HPP

#include "core/config.hpp"
#include "network/topology.hpp"

#include <cstdint>

namespace madoka {

struct HelloMessage {
    NodeId sender{};

    uint64_t timestamp{0};

    bool operator==(const HelloMessage& other) const = default;
};

HelloMessage heartbeat_create_hello(const NodeId& sender, uint64_t timestamp);

bool heartbeat_process_hello(Topology* topo,
                             const HelloMessage& hello,
                             uint64_t current_time = 0);

} // namespace madoka

#endif
