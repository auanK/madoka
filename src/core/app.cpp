#include "core/app.hpp"

#include "core/daemon.hpp"
#include "core/lifecycle.hpp"
#include "platform/private_storage.hpp"
#include "platform/random.hpp"
#include "platform/socket.hpp"

#include <charconv>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <sstream>

#ifdef _WIN32
// clang-format off
#include <windows.h>
#include <shellapi.h>
// clang-format on
#endif

namespace madoka {
namespace {

uint64_t now_milliseconds() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

uint64_t now_seconds() {
    return now_milliseconds() / 1000;
}

bool read_live_identity(const std::filesystem::path& status_path,
                        NodeId* node_id,
                        std::string* endpoint,
                        IPv6* network,
                        std::string* error) {
    std::string contents;
    if (!platform::private_read_file(status_path, 65536, &contents, nullptr)) {
        if (error != nullptr) {
            *error = "The node is not running; start madoka before creating "
                     "an invitation";
        }
        return false;
    }
    std::istringstream input(contents);
    std::string node;
    std::string updated_text;
    std::string net_text;
    std::string line;
    while (std::getline(input, line)) {
        if (line.starts_with("NODE_ID=")) {
            node = line.substr(8);
        } else if (line.starts_with("LISTEN=")) {
            *endpoint = line.substr(7);
        } else if (line.starts_with("UPDATED=")) {
            updated_text = line.substr(8);
        } else if (line.starts_with("NETWORK=")) {
            net_text = line.substr(8);
        }
    }
    uint64_t updated = 0;
    const auto [updated_end, updated_error] =
        std::from_chars(updated_text.data(),
                        updated_text.data() + updated_text.size(),
                        updated);
    const uint64_t current = now_milliseconds();
    if (updated_error != std::errc{} ||
        updated_end != updated_text.data() + updated_text.size() ||
        updated > current || current - updated > 5000) {
        if (error != nullptr) {
            *error = "The node status is stale; start madoka before creating "
                     "an invitation";
        }
        return false;
    }
    try {
        *node_id = parse_node_id(node);
    } catch (...) {
        if (error != nullptr) {
            *error = "The running node status has an invalid Node ID";
        }
        return false;
    }
    std::string address;
    uint16_t port = 0;
    if (!parse_endpoint(*endpoint, &address, &port) || port == 0) {
        if (error != nullptr) {
            *error = "The running node has no usable listen endpoint";
        }
        return false;
    }
    if (network != nullptr && !net_text.empty()) {
        if (net_text.ends_with("/64")) {
            net_text = net_text.substr(0, net_text.size() - 3);
        }
        if (inet_pton(AF_INET6, net_text.c_str(), network->data()) != 1) {
            if (error != nullptr) {
                *error =
                    "The running node status has an invalid network prefix";
            }
            return false;
        }
    }
    return true;
}

} // namespace

bool vnet_init(VirtualNetworkState* vnet,
               const Config& config,
               const Identity& identity,
               std::string* error) {
    if (!vnet) {
        return false;
    }
    vnet_shutdown(vnet);

    vnet->address = virtual_address(config.network, identity.id);
    vnet->mtu = config.mtu;
    vnet->packets_received = 0;
    vnet->packets_transmitted = 0;

    platform::TunConfig tun_cfg{
        .name = config.interface_name,
        .ipv6 = vnet->address,
        .prefix_length = 64,
        .mtu = config.mtu,
        .wintun_dll =
            config.wintun_dll.empty() ? "" : config.wintun_dll.string(),
    };

    if (!platform::tun_open(&vnet->tun, tun_cfg, error)) {
        return false;
    }

    vnet->is_up = true;
    return true;
}

void vnet_shutdown(VirtualNetworkState* vnet) {
    if (!vnet) {
        return;
    }
    if (vnet->is_up) {
        platform::tun_close(&vnet->tun);
        vnet->is_up = false;
    }
}

IPv6 generate_ula_prefix() {
    IPv6 net{};
    net[0] = 0xfd;
    platform::random_bytes(std::span<uint8_t>(net.data() + 1, 7));
    return net;
}

void save_config(const std::filesystem::path& path, const Config& config) {
    std::ostringstream out;
    out << "network=" << format_ipv6(config.network) << "/64\n";
    if (!config.identity_file.empty()) {
        out << "identity=" << config.identity_file.filename().string() << "\n";
    }
    out << "interface=" << config.interface_name << "\n";
    out << "mtu=" << config.mtu << "\n";
    out << "listen="
        << format_endpoint(config.listen_address, config.listen_port) << "\n";
    if (config.share_all_ports) {
        out << "shared_ports=all\n";
    } else if (config.shared_ports.empty()) {
        out << "shared_ports=none\n";
    } else {
        out << "shared_ports=";
        for (std::size_t i = 0; i < config.shared_ports.size(); ++i) {
            if (i > 0) {
                out << ",";
            }
            out << config.shared_ports[i];
        }
        out << "\n";
    }
    std::string err;
    platform::private_write_atomically(path, out.str(), &err);
}

bool app_init(AppState* app, int argc, char* argv[], std::string* error) {
    if (!app) {
        return false;
    }

    constexpr auto usage =
        "Usage: madoka [--listen <endpoint>] [--config <file>] [--check] "
        "[--share-ports <ports>]\n"
        "       madoka invite [--expires <minutes>] [--config <file>]\n"
        "       madoka status [--config <file>]\n"
        "       madoka join <invitation> [--listen <endpoint>] [--config "
        "<file>] [--share-ports <ports>]\n"
        "       madoka --help\n"
        "Run in the foreground; press Ctrl+C to stop.\n";

    if (argc == 2 && std::string_view{argv[1]} == "--help") {
        std::cout << usage;
        std::exit(0);
    }

#ifdef _WIN32
    int wide_count = 0;
    auto wide_args = CommandLineToArgvW(GetCommandLineW(), &wide_count);
    std::unique_ptr<void, decltype(&LocalFree)> arguments_memory(wide_args,
                                                                 LocalFree);
    if (!wide_args || wide_count != argc) {
        if (error) {
            *error = "Cannot read command-line arguments.";
        }
        return false;
    }
#endif

    std::filesystem::path config_path;
    std::string share_ports_arg;
    std::string listen_arg;
    bool check = false;
    bool status = false;
    bool invite = false;
    bool expires_set = false;

    int start_index = 1;
    if (argc >= 2 && std::string_view{argv[1]} == "status") {
        status = true;
        start_index = 2;
    } else if (argc >= 2 && std::string_view{argv[1]} == "invite") {
        invite = true;
        app->invite_mode = true;
        start_index = 2;
    } else if (argc >= 2 && std::string_view{argv[1]} == "join") {
        if (argc < 3 || std::string_view{argv[2]}.starts_with("--")) {
            std::cerr << usage;
            std::exit(2);
        }
#ifdef _WIN32
        std::wstring wendpoint = wide_args[2];
        app->join_token = std::string(wendpoint.begin(), wendpoint.end());
#else
        app->join_token = argv[2];
#endif
        if (!invite_decode(app->join_token, &app->join_invite, error)) {
            return false;
        }
        app->bootstrap_endpoint = app->join_invite.inviter_endpoint;
        app->join_mode = true;
        start_index = 3;
    }

    for (int i = start_index; i < argc; ++i) {
        const std::string_view argument{argv[i]};
        if (argument == "--config" && config_path.empty() && i + 1 < argc &&
            argv[i + 1][0] != '\0' &&
            !std::string_view{argv[i + 1]}.starts_with("--")) {
#ifdef _WIN32
            config_path = wide_args[++i];
#else
            config_path = argv[++i];
#endif
        } else if (argument == "--listen" && listen_arg.empty() &&
                   i + 1 < argc && argv[i + 1][0] != '\0' &&
                   !std::string_view{argv[i + 1]}.starts_with("--")) {
#ifdef _WIN32
            std::wstring warg = wide_args[++i];
            listen_arg = std::string(warg.begin(), warg.end());
#else
            listen_arg = argv[++i];
#endif
        } else if (argument == "--share-ports" && !status && !invite &&
                   share_ports_arg.empty() && i + 1 < argc &&
                   argv[i + 1][0] != '\0' &&
                   !std::string_view{argv[i + 1]}.starts_with("--")) {
#ifdef _WIN32
            std::wstring warg = wide_args[++i];
            share_ports_arg = std::string(warg.begin(), warg.end());
#else
            share_ports_arg = argv[++i];
#endif
        } else if (argument == "--expires" && invite && !expires_set &&
                   i + 1 < argc && argv[i + 1][0] != '\0' &&
                   !std::string_view{argv[i + 1]}.starts_with("--")) {
            expires_set = true;
            unsigned int minutes = 0;
            const std::string_view value{argv[++i]};
            const auto [end, parse_error] = std::from_chars(
                value.data(), value.data() + value.size(), minutes);
            if (parse_error != std::errc{} ||
                end != value.data() + value.size() || minutes == 0 ||
                minutes > MAX_INVITE_LIFETIME_SECONDS / 60) {
                if (error != nullptr) {
                    *error = "--expires must be between 1 and 1440 minutes";
                }
                return false;
            }
            app->invite_lifetime_seconds = static_cast<uint64_t>(minutes) * 60;
        } else if (argument == "--check" && !check && !status && !invite &&
                   !app->join_mode) {
            check = true;
        } else {
            std::cerr << usage;
            std::exit(2);
        }
    }

    const bool custom_config = !config_path.empty();
    if (!custom_config) {
        if (std::filesystem::exists("madoka.conf")) {
            config_path = "madoka.conf";
        } else {
            config_path = default_state_directory() / "madoka.conf";
        }
    }

    if (!status && !invite && !core::lifecycle_install_signals(error)) {
        return false;
    }

    if (app->join_mode) {
        if (!custom_config && std::filesystem::exists(config_path)) {
            if (error != nullptr) {
                *error =
                    "Node already has state at " + config_path.string() +
                    "; remove existing state before joining another network";
            }
            return false;
        }

        if (custom_config && std::filesystem::exists(config_path)) {
            try {
                app->config = load_config(config_path);
            } catch (const std::exception& ex) {
                if (error) {
                    *error = ex.what();
                }
                return false;
            }
        } else {
            app->config.interface_name = "madoka0";
            app->config.mtu = 1280;
            app->config.share_all_ports = true;
            app->config.identity_file =
                config_path.parent_path() / "identity.pem";
        }

        if (app->join_invite.network != IPv6{}) {
            app->config.network = app->join_invite.network;
        }
        if (!listen_arg.empty()) {
            if (!parse_endpoint(listen_arg,
                                &app->config.listen_address,
                                &app->config.listen_port)) {
                if (error != nullptr) {
                    *error = "Invalid --listen endpoint: " + listen_arg;
                }
                return false;
            }
        } else if (app->config.listen_port == 0) {
            app->config.listen_address = socket_detect_local_ip();
            app->config.listen_port =
                socket_is_port_available(app->config.listen_address, 9001)
                    ? 9001
                    : 0;
        }

        if (!share_ports_arg.empty() &&
            !parse_port_list(share_ports_arg,
                             app->config.shared_ports,
                             app->config.share_all_ports)) {
            if (error != nullptr) {
                *error = "Invalid --share-ports parameter: " + share_ports_arg;
            }
            return false;
        }

        if (custom_config &&
            std::filesystem::exists(app->config.identity_file)) {
            if (!identity_load(&app->identity, app->config, error)) {
                return false;
            }
        } else {
            if (!identity_generate(&app->identity, error)) {
                return false;
            }
            app->identity.storage_path.clear();
        }
        app->trust.directory = trust_directory(app->config.identity_file);
        app->trust.peers.clear();
    } else {
        if (!custom_config && !std::filesystem::exists(config_path)) {
            if (status || invite || check) {
                if (error != nullptr) {
                    *error =
                        "The node has not been initialized; start madoka first";
                }
                return false;
            }
            if (!platform::private_ensure_directory(config_path.parent_path(),
                                                    error)) {
                return false;
            }
            app->config.network = generate_ula_prefix();
            app->config.identity_file =
                config_path.parent_path() / "identity.pem";
            app->config.interface_name = "madoka0";
            app->config.mtu = 1280;
            app->config.share_all_ports = true;
            if (!listen_arg.empty()) {
                if (!parse_endpoint(listen_arg,
                                    &app->config.listen_address,
                                    &app->config.listen_port)) {
                    if (error != nullptr) {
                        *error = "Invalid --listen endpoint: " + listen_arg;
                    }
                    return false;
                }
            } else {
                app->config.listen_address = socket_detect_local_ip();
                app->config.listen_port =
                    socket_is_port_available(app->config.listen_address, 9001)
                        ? 9001
                        : 0;
            }
            if (!share_ports_arg.empty() &&
                !parse_port_list(share_ports_arg,
                                 app->config.shared_ports,
                                 app->config.share_all_ports)) {
                if (error != nullptr) {
                    *error =
                        "Invalid --share-ports parameter: " + share_ports_arg;
                }
                return false;
            }
            if (!identity_load(&app->identity, app->config, error)) {
                return false;
            }
            save_config(config_path, app->config);
            if (!trust_load(&app->trust, app->config.identity_file, error)) {
                identity_close(&app->identity);
                return false;
            }
        } else {
            try {
                app->config = load_config(config_path);
            } catch (const std::exception& ex) {
                if (error) {
                    *error = ex.what();
                }
                return false;
            }
            if (!listen_arg.empty()) {
                if (!parse_endpoint(listen_arg,
                                    &app->config.listen_address,
                                    &app->config.listen_port)) {
                    if (error != nullptr) {
                        *error = "Invalid --listen endpoint: " + listen_arg;
                    }
                    return false;
                }
            }
            if (!share_ports_arg.empty() &&
                !parse_port_list(share_ports_arg,
                                 app->config.shared_ports,
                                 app->config.share_all_ports)) {
                if (error != nullptr) {
                    *error =
                        "Invalid --share-ports parameter: " + share_ports_arg;
                }
                return false;
            }
            if (!status && !invite) {
                if (!identity_load(&app->identity, app->config, error)) {
                    return false;
                }
                if (!trust_load(
                        &app->trust, app->config.identity_file, error)) {
                    identity_close(&app->identity);
                    return false;
                }
            }
        }
    }

    if (!status && !invite) {
        for (const auto& peer : app->trust.peers) {
            if (!trust_address_available(app->trust,
                                         app->config.network,
                                         app->identity.id,
                                         peer.id)) {
                if (error != nullptr) {
                    *error = "Trusted peers contain a virtual address "
                             "collision";
                }
                identity_close(&app->identity);
                return false;
            }
        }
    }
    if (invite) {
        app->trust.directory = trust_directory(app->config.identity_file);
    }

    kademlia_init(&app->kademlia_table, app->identity.id);
    for (const auto& peer : app->trust.peers) {
        kademlia_insert(app->kademlia_table,
                        NodeContact{.id = peer.id,
                                    .public_key = peer.public_key,
                                    .virtual_address = virtual_address(
                                        app->config.network, peer.id),
                                    .endpoint = peer.endpoint});
    }
    topology_init(&app->topology);
    app->routing_table = routing_init();
    app->route_advertisements.clear();
    app->route_origins.clear();
    app->routing_dirty = true;
    app->next_route_sequence = 1;
    app->node_state = NodeState::CREATED;
    app->status_mode = status;
    app->check_only = check;
    app->config_path = config_path;
    app->running.store(true, std::memory_order_relaxed);
    return true;
}

int app_run(AppState* app) {
    if (!app || !app->running.load(std::memory_order_relaxed)) {
        return 1;
    }

    if (app->invite_mode) {
        NodeId node_id{};
        std::string endpoint;
        IPv6 network{};
        std::string error;
        if (!read_live_identity(app->config_path.string() + ".status",
                                &node_id,
                                &endpoint,
                                &network,
                                &error)) {
            std::cerr << error << '\n';
            return 1;
        }
        InviteTicket ticket{};
        if (!invite_generate(&ticket,
                             node_id,
                             endpoint,
                             network,
                             now_seconds(),
                             app->invite_lifetime_seconds,
                             &error) ||
            !invite_store(app->trust, ticket, &error)) {
            std::cerr << "Cannot create invitation: " << error << '\n';
            return 1;
        }
        std::cout << invite_encode(ticket) << '\n';
        return 0;
    }

    if (app->status_mode) {
        if (!app->config_path.empty()) {
            const auto status_file = app->config_path.string() + ".status";
            std::string status_contents;
            for (int attempt = 0; attempt < 20; ++attempt) {
                if (platform::private_read_file(
                        status_file, 65536, &status_contents, nullptr) &&
                    !status_contents.empty()) {
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(25));
            }
            if (!status_contents.empty()) {
                std::istringstream sf(status_contents);
                std::string line;
                std::vector<std::string> peers;
                std::vector<std::string> routes;
                std::string packets = "0";
                std::string loss = "0.0%";
                std::string trusted = "0";
                std::string node_id_str = hex(app->identity.id);
                std::string net_str = format_ipv6(app->config.network) + "/64";

                while (std::getline(sf, line)) {
                    if (line.starts_with("PEER=")) {
                        peers.push_back(line.substr(5));
                    } else if (line.starts_with("ROUTE=")) {
                        routes.push_back(line.substr(6));
                    } else if (line.starts_with("PACKETS=")) {
                        packets = line.substr(8);
                    } else if (line.starts_with("LOSS=")) {
                        loss = line.substr(5);
                    } else if (line.starts_with("TRUSTED=")) {
                        trusted = line.substr(8);
                    } else if (line.starts_with("NODE_ID=")) {
                        node_id_str = line.substr(8);
                    } else if (line.starts_with("NETWORK=")) {
                        net_str = line.substr(8);
                    }
                }

                std::cout << "Madoka Mesh\n\n"
                          << "Node:\n"
                          << node_id_str << "\n\n"
                          << "Network:\n"
                          << net_str << "\n\n\n"
                          << "Peers:\n\n";

                if (peers.empty()) {
                    std::cout << "(none)\n";
                } else {
                    for (const auto& peer : peers) {
                        std::cout << peer << "\n";
                    }
                }

                std::cout << "\n\nRoutes:\n\n";
                if (routes.empty()) {
                    std::cout << "(none)\n";
                } else {
                    for (const auto& route : routes) {
                        std::cout << route << "\n";
                    }
                }

                std::cout << "\n\nStatistics:\n\n"
                          << "Trusted peers:\n"
                          << trusted << "\n\n"
                          << "Packets:\n"
                          << packets << "\n\n"
                          << "Loss:\n"
                          << loss << "\n";
                identity_close(&app->identity);
                return 0;
            }
        }

        std::cout << "Madoka Mesh\n\nState:\nstopped\n\nNode:\n"
                  << hex(app->identity.id) << "\n\nNetwork:\n"
                  << format_ipv6(app->config.network) << "/64\n";
        identity_close(&app->identity);
        return 1;
    }

    const auto virtual_ip =
        virtual_address(app->config.network, app->identity.id);
    const auto identity_path = app->config.identity_file.generic_u8string();

    std::cout << "node_id=" << hex(app->identity.id) << '\n'
              << "ipv6=" << format_ipv6(virtual_ip) << '\n'
              << "network=" << format_ipv6(app->config.network) << "/64\n"
              << "identity_file="
              << std::string(identity_path.begin(), identity_path.end()) << '\n'
              << "trusted_peers=" << app->trust.peers.size() << '\n'
              << "interface=" << app->config.interface_name << '\n'
              << "mtu=" << app->config.mtu << '\n';

    if (app->check_only) {
        std::cout << "state=ready\n";
        identity_close(&app->identity);
        return 0;
    }

    return daemon_run(app);
}

void app_shutdown(AppState* app) {
    if (!app) {
        return;
    }
    app->running.store(false, std::memory_order_relaxed);
    app->routing_wakeup.notify_all();

    transport_server_close(&app->transport_server);

    if (app->accept_worker.joinable()) {
        app->accept_worker.join();
    }
    if (app->reconnect_worker.joinable()) {
        app->reconnect_worker.join();
    }
    if (app->data_plane_worker.joinable()) {
        app->data_plane_worker.join();
    }
    if (app->routing_worker.joinable()) {
        app->routing_worker.join();
    }

    std::vector<AppSessionWorker> workers;
    std::vector<std::shared_ptr<AppPeerSession>> sessions;
    {
        std::lock_guard<std::mutex> lock(app->sessions_mutex);
        workers.swap(app->session_workers);
        sessions = app->sessions;
    }
    for (const auto& session : sessions) {
        std::scoped_lock lock(session->send_mutex, session->receive_mutex);
        transport_close(&session->transport);
    }
    for (auto& worker : workers) {
        if (worker.thread.joinable()) {
            worker.thread.join();
        }
    }
    workers.clear();
    {
        std::lock_guard<std::mutex> lock(app->sessions_mutex);
        workers.swap(app->session_workers);
        app->sessions.clear();
    }
    for (auto& worker : workers) {
        if (worker.thread.joinable()) {
            worker.thread.join();
        }
    }

    vnet_shutdown(&app->vnet);
    identity_close(&app->identity);

    if (!app->config_path.empty()) {
        std::error_code ec;
        std::filesystem::remove(app->config_path.string() + ".status", ec);
    }
}

} // namespace madoka
