#ifndef MADOKA_PLATFORM_SOCKET_HPP
#define MADOKA_PLATFORM_SOCKET_HPP

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
using raw_socket_t = SOCKET;
constexpr raw_socket_t INVALID_SOCKET_HANDLE = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
using raw_socket_t = int;
constexpr raw_socket_t INVALID_SOCKET_HANDLE = -1;
#endif

namespace madoka {

struct SocketHandle {
    raw_socket_t fd{INVALID_SOCKET_HANDLE};
};

bool socket_init_subsystem();

SocketHandle socket_create_tcp(int family = AF_INET6);

SocketHandle socket_create_ipv6_tcp();

bool socket_is_ipv4_address(std::string_view address);

bool socket_set_reuse_addr(SocketHandle* sock);

bool socket_set_ipv6_only(SocketHandle* sock, bool v6only);

bool socket_bind(SocketHandle* sock,
                 std::string_view address,
                 uint16_t port,
                 std::string* error = nullptr);

bool socket_listen(SocketHandle* sock,
                   int backlog = 128,
                   std::string* error = nullptr);

SocketHandle
socket_accept(SocketHandle* listen_sock,
              std::string* remote_endpoint = nullptr,
              std::chrono::milliseconds timeout = std::chrono::milliseconds{0},
              std::string* error = nullptr);

SocketHandle socket_connect(std::string_view host,
                            uint16_t port,
                            std::chrono::milliseconds timeout,
                            std::string* error = nullptr);

bool socket_set_timeout(SocketHandle* sock,
                        std::chrono::milliseconds timeout,
                        bool recv,
                        bool send);

int socket_send(SocketHandle* sock,
                const uint8_t* data,
                size_t len,
                std::string* error = nullptr);

int socket_recv(SocketHandle* sock,
                uint8_t* data,
                size_t len,
                std::string* error = nullptr);

void socket_close(SocketHandle* sock);

bool socket_is_valid(const SocketHandle& sock);

bool socket_is_timeout_error(int error_code = -1);

std::string socket_last_error_text(int error_code = -1);

uint16_t socket_get_local_port(const SocketHandle& sock);

std::string socket_detect_local_ip();

bool socket_is_port_available(std::string_view address, uint16_t port);

} // namespace madoka

#endif
