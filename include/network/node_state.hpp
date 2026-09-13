#ifndef MADOKA_NETWORK_NODE_STATE_HPP
#define MADOKA_NETWORK_NODE_STATE_HPP

#include <cstdint>
#include <string>
#include <string_view>

namespace madoka {

enum class NodeState : uint8_t {
    CREATED = 0,
    DISCOVERING = 1,
    JOINING_NETWORK = 2,
    ACTIVE = 3,
    LEAVING = 4
};

[[nodiscard]] constexpr std::string_view to_string(NodeState state) noexcept {
    switch (state) {
        case NodeState::CREATED:
            return "CREATED";
        case NodeState::DISCOVERING:
            return "DISCOVERING";
        case NodeState::JOINING_NETWORK:
            return "JOINING_NETWORK";
        case NodeState::ACTIVE:
            return "ACTIVE";
        case NodeState::LEAVING:
            return "LEAVING";
    }
    return "UNKNOWN";
}

[[nodiscard]] bool node_state_can_transition(NodeState from,
                                             NodeState to) noexcept;

bool node_state_transition(NodeState& current,
                           NodeState to,
                           std::string* error = nullptr);

} // namespace madoka

#endif
