#ifndef MADOKA_CORE_CONFIG_HPP
#define MADOKA_CORE_CONFIG_HPP

#include <array>
#include <cstring>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace madoka {

using NodeId = std::array<unsigned char, 32>;

using IPv6 = std::array<unsigned char, 16>;

struct NodeIdHasher {
    std::size_t operator()(const NodeId& id) const noexcept {
        std::size_t hash = 0;
        for (std::size_t i = 0; i < id.size(); i += sizeof(std::size_t)) {
            std::size_t chunk = 0;
            std::memcpy(&chunk, id.data() + i, sizeof(chunk));
            hash ^= chunk + 0x9e3779b9 + (hash << 6) + (hash >> 2);
        }
        return hash;
    }
};

struct Config {
    IPv6 network{};

    std::filesystem::path identity_file{};

    std::string interface_name{"madoka0"};

    unsigned int mtu{1280};

    std::filesystem::path wintun_dll{};

    std::string listen_address{"::1"};

    uint16_t listen_port{0};

    std::vector<uint16_t> shared_ports{};

    bool share_all_ports{true};
};

bool parse_port_list(std::string_view value,
                     std::vector<uint16_t>& out_ports,
                     bool& out_share_all);

bool is_port_shared(const Config& config, uint16_t port) noexcept;

bool parse_endpoint(std::string_view value,
                    std::string* address,
                    uint16_t* port);

std::string format_endpoint(std::string_view address, uint16_t port);

std::string hex(std::span<const unsigned char> bytes);

NodeId parse_node_id(std::string_view value);

IPv6 virtual_address(const IPv6& network, const NodeId& id);

std::string format_ipv6(const IPv6& address);

void validate_identity_address(const NodeId& local);

Config load_config(const std::filesystem::path& path);

std::filesystem::path default_state_directory();

} // namespace madoka

#endif
