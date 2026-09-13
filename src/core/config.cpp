#include "core/config.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include <algorithm>
#include <charconv>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace madoka {
namespace {
std::string trim(std::string_view value) {
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string_view::npos) {
        return {};
    }
    return std::string{
        value.substr(begin, value.find_last_not_of(" \t\r\n") - begin + 1)};
}

bool parse_port(std::string_view value, uint16_t* port) {
    unsigned int parsed = 0;
    const auto [ptr, ec] =
        std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (ec != std::errc{} || ptr != value.data() + value.size() ||
        parsed > 65535) {
        return false;
    }
    *port = static_cast<uint16_t>(parsed);
    return true;
}

} // namespace

bool parse_endpoint(std::string_view value,
                    std::string* address,
                    uint16_t* port) {
    if (address == nullptr || port == nullptr || value.empty()) {
        return false;
    }
    if (value.front() == '[') {
        const auto close_bracket = value.find(']');
        if (close_bracket <= 1 || close_bracket == std::string_view::npos) {
            return false;
        }
        if (close_bracket + 1 >= value.size() ||
            value[close_bracket + 1] != ':') {
            return false;
        }

        const std::string parsed_address(value.substr(1, close_bracket - 1));
        IPv6 parsed_bytes{};
        if (inet_pton(AF_INET6, parsed_address.c_str(), parsed_bytes.data()) !=
            1) {
            return false;
        }

        uint16_t parsed_port = 0;
        if (!parse_port(value.substr(close_bracket + 2), &parsed_port)) {
            return false;
        }

        *address = parsed_address;
        *port = parsed_port;
        return true;
    }

    const auto last_colon = value.rfind(':');
    if (last_colon == std::string_view::npos || last_colon == 0) {
        return false;
    }
    const std::string parsed_address(value.substr(0, last_colon));
    in_addr parsed_in4{};
    if (inet_pton(AF_INET, parsed_address.c_str(), &parsed_in4) != 1) {
        return false;
    }

    uint16_t parsed_port = 0;
    if (!parse_port(value.substr(last_colon + 1), &parsed_port)) {
        return false;
    }

    *address = parsed_address;
    *port = parsed_port;
    return true;
}

std::string format_endpoint(std::string_view address, uint16_t port) {
    return address.find(':') == std::string_view::npos
               ? std::string{address} + ":" + std::to_string(port)
               : "[" + std::string{address} + "]:" + std::to_string(port);
}

bool parse_port_list(std::string_view value,
                     std::vector<uint16_t>& out_ports,
                     bool& out_share_all) {
    const auto trimmed = trim(value);
    if (trimmed.empty()) {
        return false;
    }
    if (trimmed == "all" || trimmed == "*") {
        out_share_all = true;
        out_ports.clear();
        return true;
    }
    if (trimmed == "none") {
        out_share_all = false;
        out_ports.clear();
        return true;
    }

    std::vector<uint16_t> parsed_ports;
    std::size_t start = 0;
    while (start <= trimmed.size()) {
        const auto sep = trimmed.find(',', start);
        const auto token = trim(trimmed.substr(start,
                                               sep == std::string_view::npos
                                                   ? trimmed.size() - start
                                                   : sep - start));
        if (token.empty()) {
            return false;
        }
        const auto dash = token.find('-');
        if (dash != std::string_view::npos) {
            if (dash == 0 || dash == token.size() - 1) {
                return false;
            }
            uint16_t low = 0;
            uint16_t high = 0;
            if (!parse_port(token.substr(0, dash), &low) ||
                !parse_port(token.substr(dash + 1), &high)) {
                return false;
            }
            if (low == 0 || high == 0 || low > high) {
                return false;
            }
            for (unsigned int p = low; p <= high; ++p) {
                parsed_ports.push_back(static_cast<uint16_t>(p));
            }
        } else {
            uint16_t port = 0;
            if (!parse_port(token, &port) || port == 0) {
                return false;
            }
            parsed_ports.push_back(port);
        }
        if (sep == std::string_view::npos) {
            break;
        }
        start = sep + 1;
    }

    if (parsed_ports.empty()) {
        return false;
    }
    std::sort(parsed_ports.begin(), parsed_ports.end());
    parsed_ports.erase(std::unique(parsed_ports.begin(), parsed_ports.end()),
                       parsed_ports.end());
    out_ports = std::move(parsed_ports);
    out_share_all = false;
    return true;
}

bool is_port_shared(const Config& config, uint16_t port) noexcept {
    if (config.share_all_ports) {
        return true;
    }
    return std::binary_search(
        config.shared_ports.begin(), config.shared_ports.end(), port);
}

std::string hex(std::span<const unsigned char> bytes) {
    constexpr std::string_view digits = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (const auto byte : bytes) {
        result += digits[byte >> 4];
        result += digits[byte & 15];
    }
    return result;
}

NodeId parse_node_id(std::string_view value) {
    if (value.size() != 64 ||
        value.find_first_not_of("0123456789abcdef") != value.npos) {
        throw std::runtime_error(
            "Node ID must contain exactly 64 lowercase hexadecimal digits");
    }
    NodeId result{};
    for (std::size_t i = 0; i < result.size(); ++i) {
        unsigned int byte = 0;
        std::from_chars(
            value.data() + i * 2, value.data() + i * 2 + 2, byte, 16);
        result[i] = static_cast<unsigned char>(byte);
    }
    return result;
}

IPv6 virtual_address(const IPv6& network, const NodeId& id) {
    auto address = network;
    std::copy_n(id.begin(), 8, address.begin() + 8);
    return address;
}

std::string format_ipv6(const IPv6& address) {
    std::ostringstream text;
    text << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < address.size(); i += 2) {
        if (i != 0) {
            text << ':';
        }
        text << std::setw(4)
             << (static_cast<unsigned int>(address[i]) * 256 + address[i + 1]);
    }
    return text.str();
}

void validate_identity_address(const NodeId& local) {
    if (std::all_of(local.begin(), local.begin() + 8, [](auto byte) {
            return byte == 0;
        })) {
        throw std::runtime_error(
            "Local identity derives the reserved subnet address");
    }
}

Config load_config(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw std::runtime_error("Cannot open configuration file");
    }
    std::string contents(65537, '\0');
    input.read(contents.data(), static_cast<std::streamsize>(contents.size()));
    contents.resize(static_cast<std::size_t>(input.gcount()));
    if (input.bad() || contents.size() > 65536 ||
        contents.find('\0') != contents.npos) {
        throw std::runtime_error(
            "Invalid configuration file or size exceeds 64 KiB");
    }

    Config config;
    bool has_network = false;
    bool has_identity = false;
    bool has_interface = false;
    bool has_mtu = false;
    bool has_wintun_dll = false;
    bool has_listen = false;
    bool has_shared_ports = false;
    std::istringstream lines(contents);
    std::string line;
    while (std::getline(lines, line)) {
        line = trim(line);
        if (line.empty() || line.front() == '#') {
            continue;
        }
        const auto separator = line.find('=');
        if (separator == line.npos) {
            throw std::runtime_error("Expected key=value in configuration");
        }
        const auto name = trim(std::string_view{line}.substr(0, separator));
        const auto value = trim(std::string_view{line}.substr(separator + 1));
        if (value.empty()) {
            throw std::runtime_error("Configuration values cannot be empty");
        }
        if (name == "network" && !has_network) {
            if (!value.ends_with("/64")) {
                throw std::runtime_error("network must specify /64");
            }
            const auto prefix = value.substr(0, value.size() - 3);
            if (inet_pton(AF_INET6, prefix.c_str(), config.network.data()) !=
                    1 ||
                config.network[0] != 0xfd ||
                !std::all_of(config.network.begin() + 8,
                             config.network.end(),
                             [](auto b) {
                                 return b == 0;
                             })) {
                throw std::runtime_error("network must be a locally assigned "
                                         "ULA /64 with zero host bits");
            }
            has_network = true;
        } else if (name == "identity" && !has_identity) {
            config.identity_file =
                std::filesystem::absolute(path).parent_path() /
                std::filesystem::path{
                    std::u8string(value.begin(), value.end())};
            config.identity_file = config.identity_file.lexically_normal();
            has_identity = true;
        } else if (name == "interface" && !has_interface) {
            if (value.empty() || value.size() > 15 ||
                value.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL"
                                        "MNOPQRSTUVWXYZ0123456789_") !=
                    value.npos) {
                throw std::runtime_error(
                    "Invalid interface name; must be 1-15 alphanumeric or "
                    "underscore characters");
            }
            config.interface_name = value;
            has_interface = true;
        } else if (name == "mtu" && !has_mtu) {
            unsigned int mtu_val = 0;
            const auto [ptr, ec] = std::from_chars(
                value.data(), value.data() + value.size(), mtu_val);
            if (ec != std::errc{} || ptr != value.data() + value.size() ||
                mtu_val < 1280 || mtu_val > 65535) {
                throw std::runtime_error(
                    "Invalid MTU; must be an integer between 1280 and 65535");
            }
            config.mtu = mtu_val;
            has_mtu = true;
        } else if (name == "wintun_dll" && !has_wintun_dll) {
            config.wintun_dll = std::filesystem::absolute(path).parent_path() /
                                std::filesystem::path{
                                    std::u8string(value.begin(), value.end())};
            config.wintun_dll = config.wintun_dll.lexically_normal();
            has_wintun_dll = true;
        } else if (name == "listen" && !has_listen) {
            if (!parse_endpoint(
                    value, &config.listen_address, &config.listen_port)) {
                throw std::runtime_error("Invalid listen endpoint; expected "
                                         "[IPv6]:port or IPv4:port");
            }
            has_listen = true;
        } else if (name == "shared_ports" && !has_shared_ports) {
            if (!parse_port_list(
                    value, config.shared_ports, config.share_all_ports)) {
                throw std::runtime_error(
                    "Invalid shared_ports configuration: " +
                    std::string(value));
            }
            has_shared_ports = true;
        } else {
            throw std::runtime_error(
                "Unknown or duplicate configuration field: " + name);
        }
    }
    if (!has_network) {
        throw std::runtime_error("Configuration requires network");
    }
    if (!has_identity) {
        config.identity_file =
            std::filesystem::absolute(path).parent_path() / "identity.pem";
        config.identity_file = config.identity_file.lexically_normal();
    }
    if (std::filesystem::weakly_canonical(config.identity_file) ==
        std::filesystem::weakly_canonical(path)) {
        throw std::runtime_error(
            "Identity and configuration must use different files");
    }
    return config;
}

std::filesystem::path default_state_directory() {
    if (const char* custom = std::getenv("MADOKA_STATE_DIR")) {
        if (*custom != '\0') {
            return std::filesystem::path(custom);
        }
    }
#if defined(_WIN32)
    if (const char* local_app = std::getenv("LOCALAPPDATA")) {
        if (*local_app != '\0') {
            return std::filesystem::path(local_app) / "Madoka";
        }
    }
    if (const char* user_profile = std::getenv("USERPROFILE")) {
        if (*user_profile != '\0') {
            return std::filesystem::path(user_profile) / "AppData" / "Local" /
                   "Madoka";
        }
    }
    return "Madoka";
#else
    if (const char* xdg_state = std::getenv("XDG_STATE_HOME")) {
        if (*xdg_state != '\0') {
            return std::filesystem::path(xdg_state) / "madoka";
        }
    }
    if (const char* home = std::getenv("HOME")) {
        if (*home != '\0') {
            return std::filesystem::path(home) / ".local" / "state" / "madoka";
        }
    }
    return ".madoka";
#endif
}

} // namespace madoka
