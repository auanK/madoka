#include "platform/tun.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

#ifdef _WIN32
// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <windows.h>
// clang-format on

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif
#include "platform/wintun.h"

#include <filesystem>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace madoka::platform {

#ifdef _WIN32

namespace {

HMODULE g_wintun_module = nullptr;
WINTUN_CREATE_ADAPTER_FUNC* pWintunCreateAdapter_ = nullptr;
WINTUN_CLOSE_ADAPTER_FUNC* pWintunCloseAdapter_ = nullptr;
WINTUN_START_SESSION_FUNC* pWintunStartSession_ = nullptr;
WINTUN_END_SESSION_FUNC* pWintunEndSession_ = nullptr;
WINTUN_GET_READ_WAIT_EVENT_FUNC* pWintunGetReadWaitEvent_ = nullptr;
WINTUN_RECEIVE_PACKET_FUNC* pWintunReceivePacket_ = nullptr;
WINTUN_RELEASE_RECEIVE_PACKET_FUNC* pWintunReleaseReceivePacket_ = nullptr;
WINTUN_ALLOCATE_SEND_PACKET_FUNC* pWintunAllocateSendPacket_ = nullptr;
WINTUN_SEND_PACKET_FUNC* pWintunSendPacket_ = nullptr;
WINTUN_GET_ADAPTER_LUID_FUNC* pWintunGetAdapterLUID_ = nullptr;

bool load_wintun_dll(std::string_view explicit_path, std::string* error) {
    if (g_wintun_module) {
        return true;
    }

    std::vector<std::wstring> candidate_paths;
    if (!explicit_path.empty()) {
        candidate_paths.push_back(
            std::filesystem::path(explicit_path).wstring());
    }

    wchar_t exe_buf[MAX_PATH];
    if (GetModuleFileNameW(nullptr, exe_buf, MAX_PATH) > 0) {
        std::filesystem::path exe_dir =
            std::filesystem::path(exe_buf).parent_path();
        candidate_paths.push_back((exe_dir / "wintun.dll").wstring());
    }

    candidate_paths.push_back(L"wintun.dll");
    candidate_paths.push_back(L"C:\\Program Files\\Tailscale\\wintun.dll");

    for (const auto& path : candidate_paths) {
        g_wintun_module = LoadLibraryW(path.c_str());
        if (g_wintun_module) {
            break;
        }
    }

    if (!g_wintun_module) {
        if (error) {
            *error = "Cannot find or load wintun.dll. Please ensure wintun.dll "
                     "is present.";
        }
        return false;
    }

#define LOAD_PROC(var, type, name)                                             \
    var = reinterpret_cast<type*>(GetProcAddress(g_wintun_module, name));      \
    if (!var) {                                                                \
        if (error)                                                             \
            *error = std::string("Failed to load function ") + name +          \
                     " from wintun.dll";                                       \
        FreeLibrary(g_wintun_module);                                          \
        g_wintun_module = nullptr;                                             \
        return false;                                                          \
    }

    LOAD_PROC(pWintunCreateAdapter_,
              WINTUN_CREATE_ADAPTER_FUNC,
              "WintunCreateAdapter")
    LOAD_PROC(
        pWintunCloseAdapter_, WINTUN_CLOSE_ADAPTER_FUNC, "WintunCloseAdapter")
    LOAD_PROC(
        pWintunStartSession_, WINTUN_START_SESSION_FUNC, "WintunStartSession")
    LOAD_PROC(pWintunEndSession_, WINTUN_END_SESSION_FUNC, "WintunEndSession")
    LOAD_PROC(pWintunGetReadWaitEvent_,
              WINTUN_GET_READ_WAIT_EVENT_FUNC,
              "WintunGetReadWaitEvent")
    LOAD_PROC(pWintunReceivePacket_,
              WINTUN_RECEIVE_PACKET_FUNC,
              "WintunReceivePacket")
    LOAD_PROC(pWintunReleaseReceivePacket_,
              WINTUN_RELEASE_RECEIVE_PACKET_FUNC,
              "WintunReleaseReceivePacket")
    LOAD_PROC(pWintunAllocateSendPacket_,
              WINTUN_ALLOCATE_SEND_PACKET_FUNC,
              "WintunAllocateSendPacket")
    LOAD_PROC(pWintunSendPacket_, WINTUN_SEND_PACKET_FUNC, "WintunSendPacket")
    LOAD_PROC(pWintunGetAdapterLUID_,
              WINTUN_GET_ADAPTER_LUID_FUNC,
              "WintunGetAdapterLUID")

#undef LOAD_PROC
    return true;
}

std::wstring to_wstring(std::string_view str) {
    if (str.empty())
        return {};
    int size = MultiByteToWideChar(
        CP_UTF8, 0, str.data(), static_cast<int>(str.size()), nullptr, 0);
    std::wstring result(static_cast<std::size_t>(size), 0);
    MultiByteToWideChar(CP_UTF8,
                        0,
                        str.data(),
                        static_cast<int>(str.size()),
                        result.data(),
                        size);
    return result;
}

} // namespace

bool tun_open(TunDevice* dev, const TunConfig& config, std::string* error) {
    if (!dev)
        return false;
    tun_close(dev);

    const char* mock_env = std::getenv("MADOKA_MOCK_TUN");
    if (mock_env && std::string_view(mock_env) == "1") {
        dev->name = config.name;
        dev->mtu = config.mtu;
        dev->is_open = true;
        dev->is_mock = true;
        return true;
    }

    if (!load_wintun_dll(config.wintun_dll, error)) {
        return false;
    }

    std::wstring pool_name = L"MadokaMesh";
    std::wstring adapter_name = to_wstring(config.name);

    WINTUN_ADAPTER_HANDLE adapter =
        pWintunCreateAdapter_(pool_name.c_str(), adapter_name.c_str(), nullptr);
    if (!adapter) {
        DWORD last_err = GetLastError();
        if (last_err == ERROR_ACCESS_DENIED) {
            if (error)
                *error = "Cannot create Wintun adapter: Administrator "
                         "privileges required";
        } else {
            if (error)
                *error = "WintunCreateAdapter failed with code: " +
                         std::to_string(last_err);
        }
        return false;
    }

    NET_LUID luid{};
    pWintunGetAdapterLUID_(adapter, &luid);

    MIB_IPINTERFACE_ROW if_row{};
    InitializeIpInterfaceEntry(&if_row);
    if_row.Family = AF_INET6;
    if_row.InterfaceLuid = luid;
    if (GetIpInterfaceEntry(&if_row) == NO_ERROR) {
        if_row.NlMtu = config.mtu;
        if_row.SitePrefixLength = 0;
        SetIpInterfaceEntry(&if_row);
    }

    MIB_UNICASTIPADDRESS_ROW addr_row{};
    InitializeUnicastIpAddressEntry(&addr_row);
    addr_row.InterfaceLuid = luid;
    addr_row.Address.si_family = AF_INET6;
    std::memcpy(&addr_row.Address.Ipv6.sin6_addr, config.ipv6.data(), 16);
    addr_row.OnLinkPrefixLength = static_cast<UINT8>(config.prefix_length);
    addr_row.DadState = IpDadStatePreferred;

    DWORD addr_res = CreateUnicastIpAddressEntry(&addr_row);
    if (addr_res != NO_ERROR && addr_res != ERROR_OBJECT_ALREADY_EXISTS) {
        pWintunCloseAdapter_(adapter);
        if (error) {
            *error = "CreateUnicastIpAddressEntry failed with code: " +
                     std::to_string(addr_res);
        }
        return false;
    }

    MIB_IPFORWARD_ROW2 route_row{};
    InitializeIpForwardEntry(&route_row);
    route_row.InterfaceLuid = luid;
    route_row.DestinationPrefix.Prefix.si_family = AF_INET6;
    std::memcpy(&route_row.DestinationPrefix.Prefix.Ipv6.sin6_addr,
                config.ipv6.data(),
                8);
    std::memset(reinterpret_cast<uint8_t*>(
                    &route_row.DestinationPrefix.Prefix.Ipv6.sin6_addr) +
                    8,
                0,
                8);
    route_row.DestinationPrefix.PrefixLength =
        static_cast<UINT8>(config.prefix_length);
    route_row.NextHop.si_family = AF_INET6;
    route_row.Metric = 1;
    CreateIpForwardEntry2(&route_row);

    WINTUN_SESSION_HANDLE session =
        pWintunStartSession_(adapter, WINTUN_MIN_RING_CAPACITY * 4);
    if (!session) {
        DWORD last_err = GetLastError();
        pWintunCloseAdapter_(adapter);
        if (error)
            *error = "WintunStartSession failed with code: " +
                     std::to_string(last_err);
        return false;
    }

    dev->handle = reinterpret_cast<intptr_t>(adapter);
    dev->session_handle = session;
    dev->name = config.name;
    dev->mtu = config.mtu;
    dev->is_open = true;
    return true;
}

std::size_t tun_read_packet(TunDevice* dev,
                            std::span<unsigned char> buffer,
                            std::chrono::milliseconds timeout,
                            std::string* error) {
    if (!dev || !dev->is_open) {
        if (error)
            *error = "TunDevice is not open";
        return 0;
    }
    if (dev->is_mock) {
        if (timeout.count() > 0) {
            std::this_thread::sleep_for(timeout);
        }
        return 0;
    }
    if (!dev->session_handle) {
        if (error)
            *error = "TunDevice is not open";
        return 0;
    }

    auto session = reinterpret_cast<WINTUN_SESSION_HANDLE>(dev->session_handle);
    DWORD packet_size = 0;
    BYTE* packet = pWintunReceivePacket_(session, &packet_size);

    if (!packet && timeout.count() > 0) {
        HANDLE event = pWintunGetReadWaitEvent_(session);
        if (event &&
            WaitForSingleObject(event, static_cast<DWORD>(timeout.count())) ==
                WAIT_OBJECT_0) {
            packet = pWintunReceivePacket_(session, &packet_size);
        }
    }

    if (!packet) {
        return 0;
    }

    const std::size_t copy_size =
        std::min<std::size_t>(buffer.size(), packet_size);
    std::memcpy(buffer.data(), packet, copy_size);
    pWintunReleaseReceivePacket_(session, packet);
    return copy_size;
}

bool tun_write_packet(TunDevice* dev,
                      std::span<const unsigned char> packet,
                      std::string* error) {
    if (!dev || !dev->is_open) {
        if (error)
            *error = "TunDevice is not open";
        return false;
    }
    if (dev->is_mock) {
        return true;
    }
    if (!dev->session_handle) {
        if (error)
            *error = "TunDevice is not open";
        return false;
    }
    if (packet.empty() || packet.size() > WINTUN_MAX_IP_PACKET_SIZE) {
        if (error)
            *error = "Invalid packet size for Wintun transmission";
        return false;
    }

    auto session = reinterpret_cast<WINTUN_SESSION_HANDLE>(dev->session_handle);
    BYTE* buf =
        pWintunAllocateSendPacket_(session, static_cast<DWORD>(packet.size()));
    if (!buf) {
        if (error)
            *error = "Wintun ring buffer full or exhausted";
        return false;
    }

    std::memcpy(buf, packet.data(), packet.size());
    pWintunSendPacket_(session, buf);
    return true;
}

void tun_close(TunDevice* dev) {
    if (!dev)
        return;
    if (dev->is_mock) {
        dev->is_open = false;
        dev->is_mock = false;
        return;
    }
    if (dev->session_handle) {
        pWintunEndSession_(
            reinterpret_cast<WINTUN_SESSION_HANDLE>(dev->session_handle));
        dev->session_handle = nullptr;
    }
    if (dev->handle != -1) {
        pWintunCloseAdapter_(
            reinterpret_cast<WINTUN_ADAPTER_HANDLE>(dev->handle));
        dev->handle = -1;
    }
    dev->is_open = false;
}

bool tun_is_open(const TunDevice& dev) {
    return dev.is_open &&
           (dev.is_mock || (dev.handle != -1 && dev.session_handle != nullptr));
}

#else

bool tun_open(TunDevice* dev, const TunConfig& config, std::string* error) {
    if (!dev)
        return false;
    tun_close(dev);

    const char* mock_env = std::getenv("MADOKA_MOCK_TUN");
    if (mock_env && std::string_view(mock_env) == "1") {
        dev->name = config.name;
        dev->mtu = config.mtu;
        dev->is_open = true;
        dev->is_mock = true;
        return true;
    }

    int fd = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        if (errno == EACCES || errno == EPERM) {
            if (error)
                *error = "Cannot open /dev/net/tun: CAP_NET_ADMIN or root "
                         "privileges required";
        } else {
            if (error)
                *error = "Cannot open /dev/net/tun: " +
                         std::string(std::strerror(errno));
        }
        return false;
    }

    struct ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    std::strncpy(ifr.ifr_name, config.name.c_str(), IFNAMSIZ - 1);

    if (::ioctl(fd, TUNSETIFF, &ifr) < 0) {
        if (error)
            *error = "TUNSETIFF failed: " + std::string(std::strerror(errno));
        ::close(fd);
        return false;
    }

    std::string assigned_name = ifr.ifr_name;

    int sock = ::socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) {
        sock = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    }
    if (sock >= 0) {
        ifr.ifr_mtu = static_cast<int>(config.mtu);
        ::ioctl(sock, SIOCSIFMTU, &ifr);
    }

    const int nl_fd =
        ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (nl_fd >= 0) {
        struct {
            struct nlmsghdr n;
            struct ifaddrmsg ifa;
            char buf[256];
        } req{};
        req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
        req.n.nlmsg_flags =
            NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
        req.n.nlmsg_type = RTM_NEWADDR;
        req.ifa.ifa_family = AF_INET6;
        req.ifa.ifa_prefixlen =
            static_cast<unsigned char>(config.prefix_length);
        req.ifa.ifa_flags = IFA_F_PERMANENT;
        req.ifa.ifa_scope = RT_SCOPE_UNIVERSE;
        req.ifa.ifa_index = if_nametoindex(assigned_name.c_str());

        auto* rta = reinterpret_cast<struct rtattr*>(
            reinterpret_cast<char*>(&req) + NLMSG_ALIGN(req.n.nlmsg_len));
        rta->rta_type = IFA_LOCAL;
        rta->rta_len = RTA_LENGTH(16);
        std::memcpy(RTA_DATA(rta), config.ipv6.data(), 16);
        req.n.nlmsg_len =
            NLMSG_ALIGN(req.n.nlmsg_len) + RTA_ALIGN(rta->rta_len);

        auto* rta2 = reinterpret_cast<struct rtattr*>(
            reinterpret_cast<char*>(&req) + NLMSG_ALIGN(req.n.nlmsg_len));
        rta2->rta_type = IFA_ADDRESS;
        rta2->rta_len = RTA_LENGTH(16);
        std::memcpy(RTA_DATA(rta2), config.ipv6.data(), 16);
        req.n.nlmsg_len =
            NLMSG_ALIGN(req.n.nlmsg_len) + RTA_ALIGN(rta2->rta_len);

        ::send(nl_fd, &req, req.n.nlmsg_len, 0);

        char ack_buf[256];
        ::recv(nl_fd, ack_buf, sizeof(ack_buf), 0);
        ::close(nl_fd);
    }

    if (sock >= 0) {
        if (::ioctl(sock, SIOCGIFFLAGS, &ifr) >= 0) {
            ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
            ::ioctl(sock, SIOCSIFFLAGS, &ifr);
        }
        ::close(sock);
    }

    dev->handle = fd;
    dev->session_handle = nullptr;
    dev->name = assigned_name;
    dev->mtu = config.mtu;
    dev->is_open = true;
    return true;
}

std::size_t tun_read_packet(TunDevice* dev,
                            std::span<unsigned char> buffer,
                            std::chrono::milliseconds timeout,
                            std::string* error) {
    if (!dev || !dev->is_open) {
        if (error)
            *error = "TunDevice is not open";
        return 0;
    }
    if (dev->is_mock) {
        if (timeout.count() > 0) {
            std::this_thread::sleep_for(timeout);
        }
        return 0;
    }
    if (dev->handle < 0) {
        if (error)
            *error = "TunDevice is not open";
        return 0;
    }

    int fd = static_cast<int>(dev->handle);
    if (timeout.count() >= 0) {
        struct pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLIN;
        const int poll_res = ::poll(&pfd, 1, static_cast<int>(timeout.count()));
        if (poll_res <= 0) {
            return 0;
        }
    }

    const ssize_t count = ::read(fd, buffer.data(), buffer.size());
    return count > 0 ? static_cast<std::size_t>(count) : 0;
}

bool tun_write_packet(TunDevice* dev,
                      std::span<const unsigned char> packet,
                      std::string* error) {
    if (!dev || !dev->is_open) {
        if (error)
            *error = "TunDevice is not open";
        return false;
    }
    if (dev->is_mock) {
        return true;
    }
    if (dev->handle < 0) {
        if (error)
            *error = "TunDevice is not open";
        return false;
    }
    int fd = static_cast<int>(dev->handle);
    const ssize_t written = ::write(fd, packet.data(), packet.size());
    if (written < 0) {
        if (error)
            *error = "tun_write failed: " + std::string(std::strerror(errno));
        return false;
    }
    return true;
}

void tun_close(TunDevice* dev) {
    if (!dev)
        return;
    if (dev->is_mock) {
        dev->is_open = false;
        dev->is_mock = false;
        return;
    }
    if (dev->handle >= 0) {
        ::close(static_cast<int>(dev->handle));
        dev->handle = -1;
    }
    dev->is_open = false;
}

bool tun_is_open(const TunDevice& dev) {
    return dev.is_open && (dev.is_mock || dev.handle >= 0);
}

#endif

} // namespace madoka::platform
