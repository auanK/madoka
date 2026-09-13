#ifndef MADOKA_CORE_APP_HPP
#define MADOKA_CORE_APP_HPP

#include "core/config.hpp"
#include "crypto/identity.hpp"
#include "network/distance_vector.hpp"
#include "network/kademlia.hpp"
#include "network/node_state.hpp"
#include "network/route_advertisement.hpp"
#include "network/routing.hpp"
#include "network/topology.hpp"
#include "platform/tun.hpp"
#include "security/invite.hpp"
#include "transport/session.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace madoka {

struct VirtualNetworkState {
    platform::TunDevice tun{};
    IPv6 address{};
    unsigned int mtu{1280};
    uint64_t packets_received{0};
    uint64_t packets_transmitted{0};
    bool is_up{false};
};

bool vnet_init(VirtualNetworkState* vnet,
               const Config& config,
               const Identity& identity,
               std::string* error = nullptr);

void vnet_shutdown(VirtualNetworkState* vnet);

IPv6 generate_ula_prefix();

void save_config(const std::filesystem::path& path, const Config& config);

struct AppPeerSession {
    TransportSessionState transport{};
    NodeContact contact{};
    std::optional<NodeId> peer_id{std::nullopt};
    std::mutex send_mutex{};
    std::mutex receive_mutex{};
    bool worker_started{false};

    bool trusted{false};
};

struct DataPlaneMetrics {
    std::atomic_uint64_t tun_packets_read{0};
    std::atomic_uint64_t tun_packets_written{0};
    std::atomic_uint64_t data_messages_sent{0};
    std::atomic_uint64_t data_messages_received{0};
    std::atomic_uint64_t drop_no_active_peer{0};
    std::atomic_uint64_t drop_invalid_ipv6{0};
    std::atomic_uint64_t drop_wrong_destination{0};
    std::atomic_uint64_t drop_oversized{0};
    std::atomic_uint64_t drop_transport_error{0};
    std::atomic_uint64_t drop_malformed_data_message{0};
    std::atomic_uint64_t drop_unshared_port{0};
};

struct RoutingMetrics {
    std::atomic_uint64_t routes_installed{0};
    std::atomic_uint64_t routes_updated{0};
    std::atomic_uint64_t routes_expired{0};
    std::atomic_uint64_t route_advertisements_sent{0};
    std::atomic_uint64_t route_advertisements_received{0};
    std::atomic_uint64_t route_advertisements_stale{0};
    std::atomic_uint64_t forwarded_packets{0};
    std::atomic_uint64_t delivered_local_packets{0};
    std::atomic_uint64_t drop_no_route{0};
    std::atomic_uint64_t drop_next_hop_unavailable{0};
    std::atomic_uint64_t drop_ttl_expired{0};
    std::atomic_uint64_t drop_invalid_route_advertisement{0};
    std::atomic_uint64_t neighbor_up{0};
    std::atomic_uint64_t neighbor_down{0};
};

struct StoredRouteAdvertisement {
    RouteAdvertisement advertisement{};
    uint64_t received_at_ms{0};
};

struct AppSessionWorker {
    std::thread thread{};
    std::shared_ptr<std::atomic_bool> finished{};
};

struct AppState {
    Config config{};
    Identity identity{};
    TrustState trust{};
    std::mutex trust_mutex{};
    VirtualNetworkState vnet{};
    KademliaTable kademlia_table{};
    std::mutex kademlia_mutex{};
    Topology topology{};
    std::mutex topology_mutex{};
    RoutingTable routing_table{};
    std::mutex routing_mutex{};
    std::unordered_map<NodeId, StoredRouteAdvertisement, NodeIdHasher>
        route_advertisements{};
    RouteOriginStates route_origins{};
    std::condition_variable routing_wakeup{};
    std::mutex routing_wakeup_mutex{};
    bool routing_dirty{true};
    uint64_t next_route_sequence{1};
    std::atomic_uint64_t next_control_sequence{1};
    TransportServerState transport_server{};
    NodeContact local_contact{};
    std::mutex sessions_mutex{};
    std::vector<std::shared_ptr<AppPeerSession>> sessions{};
    std::vector<AppSessionWorker> session_workers{};
    std::thread accept_worker{};
    std::thread routing_worker{};
    std::thread data_plane_worker{};
    std::thread reconnect_worker{};
    std::mutex tun_write_mutex{};
    std::mutex outbound_ports_mutex{};
    std::unordered_map<uint16_t, std::chrono::steady_clock::time_point>
        active_outbound_ports{};
    std::atomic_uint64_t next_packet_id{1};
    DataPlaneMetrics data_metrics{};
    RoutingMetrics routing_metrics{};
    NodeState node_state{NodeState::CREATED};
    std::atomic_bool running{false};
    bool check_only{false};
    bool status_mode{false};
    bool join_mode{false};
    bool invite_mode{false};
    uint64_t invite_lifetime_seconds{DEFAULT_INVITE_LIFETIME_SECONDS};
    InviteTicket join_invite{};
    std::string join_token{};
    std::string bootstrap_endpoint{};
    std::filesystem::path config_path{};
};

bool app_init(AppState* app,
              int argc,
              char* argv[],
              std::string* error = nullptr);

int app_run(AppState* app);

void app_shutdown(AppState* app);

} // namespace madoka

#endif
