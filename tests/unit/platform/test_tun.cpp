#include "platform/tun.hpp"

#include <array>
#include <chrono>
#include <iostream>
#include <vector>

int main() {
    std::array<unsigned char, 16> ipv6{0xfd,
                                       0x12,
                                       0x34,
                                       0x56,
                                       0x78,
                                       0x9a,
                                       0x00,
                                       0x01,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x00,
                                       0x99};

    madoka::platform::TunConfig cfg{
        .name = "madokatest99", .ipv6 = ipv6, .prefix_length = 64, .mtu = 1280};

    madoka::platform::TunDevice dev{};
    std::string err;

    if (!madoka::platform::tun_open(&dev, cfg, &err)) {
        std::cout << "Tun test open (expected if unprivileged): " << err
                  << '\n';

        return 0;
    }

    std::cout << "Opened interface: " << dev.name << " with MTU: " << dev.mtu
              << '\n';

    std::vector<unsigned char> packet(40, 0);
    packet[0] = 0x60;
    packet[6] = 59;
    packet[7] = 64;
    packet[8] = 0xfe;
    packet[9] = 0x80;
    packet[23] = 0x01;
    std::copy(ipv6.begin(), ipv6.end(), packet.begin() + 24);

    if (!madoka::platform::tun_write_packet(&dev, packet, &err)) {
        std::cout << "tun_write_packet failed: " << err << '\n';
    } else {
        std::cout
            << "Successfully wrote 40-byte IPv6 packet to TUN interface\n";
    }

    std::vector<unsigned char> read_buf(1500);
    std::size_t bytes = madoka::platform::tun_read_packet(
        &dev, read_buf, std::chrono::milliseconds{10});
    std::cout << "tun_read_packet returned: " << bytes << " bytes\n";

    madoka::platform::tun_close(&dev);
    std::cout << "Tun interface closed successfully.\n";
    return 0;
}
