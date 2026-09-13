#include "network/node_state.hpp"

namespace madoka {

bool node_state_can_transition(NodeState from, NodeState to) noexcept {
    switch (from) {
        case NodeState::CREATED:
            return to == NodeState::DISCOVERING;

        case NodeState::DISCOVERING:
            return to == NodeState::JOINING_NETWORK ||
                   to == NodeState::ACTIVE || to == NodeState::DISCOVERING ||
                   to == NodeState::LEAVING;

        case NodeState::JOINING_NETWORK:
            return to == NodeState::ACTIVE || to == NodeState::DISCOVERING ||
                   to == NodeState::LEAVING;

        case NodeState::ACTIVE:
            return to == NodeState::LEAVING || to == NodeState::DISCOVERING;

        case NodeState::LEAVING:
            return to == NodeState::CREATED;
    }
    return false;
}

bool node_state_transition(NodeState& current,
                           NodeState to,
                           std::string* error) {
    if (!node_state_can_transition(current, to)) {
        if (error != nullptr) {
            *error = "Invalid state transition from " +
                     std::string(to_string(current)) + " to " +
                     std::string(to_string(to));
        }
        return false;
    }

    current = to;
    return true;
}

} // namespace madoka
