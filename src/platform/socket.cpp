#include "platform/socket.hpp"

#include <cstring>
#include <memory>

#if !defined(_WIN32)
#include <csignal>
#include <netdb.h>
#endif

namespace madoka {

namespace {

#if defined(_WIN32)
struct WinsockScope {
    WinsockScope() {
        WSADATA data;
        ::WSAStartup(MAKEWORD(2, 2), &data);
    }
    ~WinsockScope() {
        ::WSACleanup();
    }
};

void ensure_initialized() {
    static WinsockScope scope;
    (void)scope;
}
#else
struct PosixInit {
    PosixInit() {
        std::signal(SIGPIPE, SIG_IGN);
    }
};

void ensure_initialized() {
    static PosixInit init;
    (void)init;
}
#endif

} // namespace

bool socket_init_subsystem() {
    ensure_initialized();
    return true;
}

SocketHandle socket_create_tcp(int family) {
    ensure_initialized();
    raw_socket_t fd = ::socket(family, SOCK_STREAM, IPPROTO_TCP);
    return SocketHandle{fd};
}

SocketHandle socket_create_ipv6_tcp() {
    return socket_create_tcp(AF_INET6);
}

bool socket_is_ipv4_address(std::string_view address) {
    in_addr in4{};
    const std::string addr_str(address);
    return ::inet_pton(AF_INET, addr_str.c_str(), &in4) == 1;
}

bool socket_set_reuse_addr(SocketHandle* sock) {
    if (!sock || !socket_is_valid(*sock))
        return false;
    int reuse = 1;
    return ::setsockopt(sock->fd,
                        SOL_SOCKET,
                        SO_REUSEADDR,
                        reinterpret_cast<const char*>(&reuse),
                        sizeof(reuse)) == 0;
}

bool socket_set_ipv6_only(SocketHandle* sock, bool v6only) {
    if (!sock || !socket_is_valid(*sock))
        return false;
    int val = v6only ? 1 : 0;
    return ::setsockopt(sock->fd,
                        IPPROTO_IPV6,
                        IPV6_V6ONLY,
                        reinterpret_cast<const char*>(&val),
                        sizeof(val)) == 0;
}

bool socket_bind(SocketHandle* sock,
                 std::string_view address,
                 uint16_t port,
                 std::string* error) {
    if (!sock || !socket_is_valid(*sock)) {
        if (error)
            *error = "Invalid socket handle";
        return false;
    }

    const std::string addr_str(address);
    if (socket_is_ipv4_address(address)) {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (::inet_pton(AF_INET, addr_str.c_str(), &addr.sin_addr) <= 0) {
            if (error)
                *error = "Invalid IPv4 address: " + addr_str;
            return false;
        }
        if (::bind(sock->fd,
                   reinterpret_cast<const sockaddr*>(&addr),
                   sizeof(addr)) != 0) {
            if (error)
                *error = "Bind failed: " + socket_last_error_text();
            return false;
        }
        return true;
    }

    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);

    if (::inet_pton(AF_INET6, addr_str.c_str(), &addr.sin6_addr) <= 0) {
        if (error)
            *error = "Invalid IPv6 address: " + addr_str;
        return false;
    }

    if (::bind(sock->fd,
               reinterpret_cast<const sockaddr*>(&addr),
               sizeof(addr)) != 0) {
        if (error)
            *error = "Bind failed: " + socket_last_error_text();
        return false;
    }
    return true;
}

bool socket_listen(SocketHandle* sock, int backlog, std::string* error) {
    if (!sock || !socket_is_valid(*sock)) {
        if (error)
            *error = "Invalid socket handle";
        return false;
    }
    if (::listen(sock->fd, backlog) != 0) {
        if (error)
            *error = "Listen failed: " + socket_last_error_text();
        return false;
    }
    return true;
}

SocketHandle socket_accept(SocketHandle* listen_sock,
                           std::string* remote_endpoint,
                           std::chrono::milliseconds timeout,
                           std::string* error) {
    if (!listen_sock || !socket_is_valid(*listen_sock)) {
        if (error)
            *error = "Invalid listening socket handle";
        return SocketHandle{INVALID_SOCKET_HANDLE};
    }

    if (timeout.count() > 0) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(listen_sock->fd, &read_fds);
        timeval tv{};
        tv.tv_sec = static_cast<long>(timeout.count() / 1000);
        tv.tv_usec = static_cast<long>((timeout.count() % 1000) * 1000);
#if defined(_WIN32)
        int res = ::select(0, &read_fds, nullptr, nullptr, &tv);
#else
        int res =
            ::select(listen_sock->fd + 1, &read_fds, nullptr, nullptr, &tv);
#endif
        if (res <= 0) {
            return SocketHandle{INVALID_SOCKET_HANDLE};
        }
    }

    sockaddr_storage client_addr{};
#if defined(_WIN32)
    int addr_len = sizeof(client_addr);
#else
    socklen_t addr_len = sizeof(client_addr);
#endif

    raw_socket_t client_fd = ::accept(
        listen_sock->fd, reinterpret_cast<sockaddr*>(&client_addr), &addr_len);
    if (client_fd == INVALID_SOCKET_HANDLE) {
        if (error)
            *error = socket_last_error_text();
        return SocketHandle{INVALID_SOCKET_HANDLE};
    }

    if (remote_endpoint) {
        if (client_addr.ss_family == AF_INET) {
            auto* sin = reinterpret_cast<sockaddr_in*>(&client_addr);
            char ip_str[INET_ADDRSTRLEN] = {0};
            ::inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));
            *remote_endpoint = std::string(ip_str) + ":" +
                               std::to_string(ntohs(sin->sin_port));
        } else {
            auto* sin6 = reinterpret_cast<sockaddr_in6*>(&client_addr);
            char ip_str[INET6_ADDRSTRLEN] = {0};
            ::inet_ntop(AF_INET6, &sin6->sin6_addr, ip_str, sizeof(ip_str));
            *remote_endpoint = "[" + std::string(ip_str) +
                               "]:" + std::to_string(ntohs(sin6->sin6_port));
        }
    }

    return SocketHandle{client_fd};
}

SocketHandle socket_connect(std::string_view host,
                            uint16_t port,
                            std::chrono::milliseconds timeout,
                            std::string* error) {
    ensure_initialized();

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    const std::string port_str = std::to_string(port);
    const std::string host_str(host);
    addrinfo* result_list = nullptr;

    int res =
        ::getaddrinfo(host_str.c_str(), port_str.c_str(), &hints, &result_list);
    if (res != 0) {
        if (error)
            *error = "getaddrinfo failed: " + std::string(gai_strerror(res));
        return SocketHandle{INVALID_SOCKET_HANDLE};
    }

    std::unique_ptr<addrinfo, decltype(&::freeaddrinfo)> addr_guard(
        result_list, ::freeaddrinfo);

    std::string last_err_text;
    for (addrinfo* ptr = result_list; ptr != nullptr; ptr = ptr->ai_next) {
        raw_socket_t fd =
            ::socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (fd == INVALID_SOCKET_HANDLE)
            continue;

        SocketHandle sock{fd};
        if (timeout.count() > 0) {
            socket_set_timeout(&sock, timeout, true, true);
        }

        if (::connect(sock.fd,
                      ptr->ai_addr,
                      static_cast<int>(ptr->ai_addrlen)) == 0) {
            return sock;
        }

#if defined(_WIN32)
        int err_code = ::WSAGetLastError();
#else
        int err_code = errno;
#endif
        last_err_text = socket_last_error_text(err_code);
        socket_close(&sock);
    }

    if (error)
        *error = "Connection to " + host_str + ":" + port_str +
                 " failed: " + last_err_text;
    return SocketHandle{INVALID_SOCKET_HANDLE};
}

bool socket_set_timeout(SocketHandle* sock,
                        std::chrono::milliseconds timeout,
                        bool recv,
                        bool send) {
    if (!sock || !socket_is_valid(*sock))
        return false;

#if defined(_WIN32)
    DWORD ms = static_cast<DWORD>(timeout.count());
    if (recv) {
        ::setsockopt(sock->fd,
                     SOL_SOCKET,
                     SO_RCVTIMEO,
                     reinterpret_cast<const char*>(&ms),
                     sizeof(ms));
    }
    if (send) {
        ::setsockopt(sock->fd,
                     SOL_SOCKET,
                     SO_SNDTIMEO,
                     reinterpret_cast<const char*>(&ms),
                     sizeof(ms));
    }
    return true;
#else
    struct timeval tv{};
    tv.tv_sec = static_cast<time_t>(timeout.count() / 1000);
    tv.tv_usec = static_cast<suseconds_t>((timeout.count() % 1000) * 1000);
    if (recv) {
        ::setsockopt(sock->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    if (send) {
        ::setsockopt(sock->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
    return true;
#endif
}

int socket_send(SocketHandle* sock,
                const uint8_t* data,
                size_t len,
                std::string* error) {
    if (!sock || !socket_is_valid(*sock)) {
        if (error)
            *error = "Invalid socket handle";
        return -1;
    }
    int sent = ::send(sock->fd,
                      reinterpret_cast<const char*>(data),
                      static_cast<int>(len),
                      0);
    if (sent < 0 && error) {
        *error = socket_last_error_text();
    }
    return sent;
}

int socket_recv(SocketHandle* sock,
                uint8_t* data,
                size_t len,
                std::string* error) {
    if (!sock || !socket_is_valid(*sock)) {
        if (error)
            *error = "Invalid socket handle";
        return -1;
    }
    int bytes = ::recv(
        sock->fd, reinterpret_cast<char*>(data), static_cast<int>(len), 0);
    if (bytes < 0 && error) {
        *error = socket_last_error_text();
    }
    return bytes;
}

void socket_close(SocketHandle* sock) {
    if (sock && socket_is_valid(*sock)) {
#if defined(_WIN32)
        ::closesocket(sock->fd);
#else
        ::close(sock->fd);
#endif
        sock->fd = INVALID_SOCKET_HANDLE;
    }
}

bool socket_is_valid(const SocketHandle& sock) {
    return sock.fd != INVALID_SOCKET_HANDLE;
}

bool socket_is_timeout_error(int error_code) {
#if defined(_WIN32)
    if (error_code < 0)
        error_code = ::WSAGetLastError();
    return error_code == WSAETIMEDOUT || error_code == WSAEWOULDBLOCK;
#else
    if (error_code < 0)
        error_code = errno;
    return error_code == EAGAIN || error_code == EWOULDBLOCK ||
           error_code == ETIMEDOUT;
#endif
}

std::string socket_last_error_text(int error_code) {
#if defined(_WIN32)
    if (error_code < 0)
        error_code = ::WSAGetLastError();
    char* message = nullptr;
    DWORD len = ::FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                                     FORMAT_MESSAGE_FROM_SYSTEM |
                                     FORMAT_MESSAGE_IGNORE_INSERTS,
                                 nullptr,
                                 static_cast<DWORD>(error_code),
                                 MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                 reinterpret_cast<LPSTR>(&message),
                                 0,
                                 nullptr);
    std::string text;
    if (len > 0 && message != nullptr) {
        text.assign(message, len);
        while (!text.empty() && (text.back() == '\r' || text.back() == '\n' ||
                                 text.back() == ' ')) {
            text.pop_back();
        }
        ::LocalFree(message);
    } else {
        text = "WSA error " + std::to_string(error_code);
    }
    return text;
#else
    if (error_code < 0)
        error_code = errno;
    return std::strerror(error_code);
#endif
}

uint16_t socket_get_local_port(const SocketHandle& sock) {
    if (!socket_is_valid(sock))
        return 0;
    sockaddr_in6 addr{};
#if defined(_WIN32)
    int len = sizeof(addr);
#else
    socklen_t len = sizeof(addr);
#endif
    if (::getsockname(sock.fd, reinterpret_cast<sockaddr*>(&addr), &len) == 0) {
        return ntohs(addr.sin6_port);
    }
    return 0;
}

std::string socket_detect_local_ip() {
    socket_init_subsystem();
    raw_socket_t s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET_HANDLE) {
        return "127.0.0.1";
    }
    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &target.sin_addr);
    if (::connect(s, reinterpret_cast<sockaddr*>(&target), sizeof(target)) ==
        0) {
        sockaddr_in local{};
#if defined(_WIN32)
        int len = sizeof(local);
#else
        socklen_t len = sizeof(local);
#endif
        if (::getsockname(s, reinterpret_cast<sockaddr*>(&local), &len) == 0) {
            char buf[INET_ADDRSTRLEN]{};
            inet_ntop(AF_INET, &local.sin_addr, buf, sizeof(buf));
#if defined(_WIN32)
            ::closesocket(s);
#else
            ::close(s);
#endif
            std::string ip(buf);
            if (!ip.empty() && ip != "0.0.0.0") {
                return ip;
            }
            return "127.0.0.1";
        }
    }
#if defined(_WIN32)
    ::closesocket(s);
#else
    ::close(s);
#endif
    return "127.0.0.1";
}

bool socket_is_port_available(std::string_view address, uint16_t port) {
    socket_init_subsystem();
    SocketHandle s = socket_create_tcp(
        address.find(':') != std::string_view::npos ? AF_INET6 : AF_INET);
    if (!socket_is_valid(s)) {
        return false;
    }
    socket_set_reuse_addr(&s);
    bool ok = socket_bind(&s, address, port);
    socket_close(&s);
    return ok;
}

} // namespace madoka
