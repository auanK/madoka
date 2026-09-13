#ifndef MADOKA_PLATFORM_TUN_HPP
#define MADOKA_PLATFORM_TUN_HPP

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace madoka::platform {

struct TunConfig {
    std::string name{"madoka0"};
    std::array<unsigned char, 16> ipv6{};
    unsigned int prefix_length{64};
    unsigned int mtu{1280};
    std::string wintun_dll{};
};

struct TunDevice {
    intptr_t handle{-1};
    void* session_handle{nullptr};
    std::string name{};
    unsigned int mtu{1280};
    bool is_open{false};
    bool is_mock{false};
};

bool tun_open(TunDevice* dev,
              const TunConfig& config,
              std::string* error = nullptr);

std::size_t tun_read_packet(
    TunDevice* dev,
    std::span<unsigned char> buffer,
    std::chrono::milliseconds timeout = std::chrono::milliseconds{0},
    std::string* error = nullptr);

bool tun_write_packet(TunDevice* dev,
                      std::span<const unsigned char> packet,
                      std::string* error = nullptr);

void tun_close(TunDevice* dev);

bool tun_is_open(const TunDevice& dev);

} // namespace madoka::platform

#endif
