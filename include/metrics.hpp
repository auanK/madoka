#ifndef MADOKA_METRICS_HPP
#define MADOKA_METRICS_HPP

#include <cstdint>

namespace madoka {

struct ForwardingMetrics {
    uint64_t forwarded_packets{0};

    uint64_t dropped_packets{0};

    uint64_t ttl_expired_packets{0};

    uint64_t unknown_destination_packets{0};

    bool operator==(const ForwardingMetrics& other) const = default;
};

} // namespace madoka

#endif
