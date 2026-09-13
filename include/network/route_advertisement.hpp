#ifndef MADOKA_NETWORK_ROUTE_ADVERTISEMENT_HPP
#define MADOKA_NETWORK_ROUTE_ADVERTISEMENT_HPP

#include "core/config.hpp"
#include "network/route.hpp"
#include "network/routing.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace madoka {

enum class SplitHorizonMode : uint8_t {
    Disabled = 0,
    SplitHorizon = 1,
    PoisonReverse = 2
};

struct RouteAdvertisement {
    NodeId sender{};

    uint64_t generation{0};

    uint64_t sequence_number{0};

    std::vector<Route> routes{};

    bool operator==(const RouteAdvertisement& other) const = default;
};

RouteAdvertisement route_create_advertisement(
    const NodeId& sender,
    const RouteTable& table,
    uint64_t sequence_number = 0,
    const std::optional<NodeId>& target_neighbor = std::nullopt,
    SplitHorizonMode mode = SplitHorizonMode::Disabled,
    uint64_t generation = 0);

bool validate_route_advertisement(const RouteAdvertisement& advertisement,
                                  const IPv6& network,
                                  std::string* error = nullptr);

} // namespace madoka

#endif
