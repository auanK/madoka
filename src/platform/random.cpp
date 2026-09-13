#include "platform/random.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <limits>

#if defined(_WIN32)
// clang-format off
#include <windows.h>
#include <bcrypt.h>
// clang-format on
#elif defined(__linux__)
#include <sys/random.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace madoka::platform {

bool random_bytes(std::span<uint8_t> output, std::string* error) {
    if (output.empty()) {
        return true;
    }

#if defined(_WIN32)
    std::size_t offset = 0;
    while (offset < output.size()) {
        const auto remaining = output.size() - offset;
        const auto count = static_cast<ULONG>(std::min(
            remaining,
            static_cast<std::size_t>((std::numeric_limits<ULONG>::max)())));
        const auto status = BCryptGenRandom(nullptr,
                                            output.data() + offset,
                                            count,
                                            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status != 0) {
            if (error != nullptr) {
                *error = "BCryptGenRandom failed: " +
                         std::to_string(static_cast<unsigned long>(status));
            }
            return false;
        }
        offset += count;
    }
    return true;
#elif defined(__linux__)
    std::size_t offset = 0;
    while (offset < output.size()) {
        const auto count =
            ::getrandom(output.data() + offset, output.size() - offset, 0);
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (error != nullptr) {
                *error =
                    "getrandom failed: " + std::string{std::strerror(errno)};
            }
            return false;
        }
        if (count == 0) {
            if (error != nullptr) {
                *error = "getrandom returned no data";
            }
            return false;
        }
        offset += static_cast<std::size_t>(count);
    }
    return true;
#else
    int flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    const int descriptor = ::open("/dev/urandom", flags);
    if (descriptor < 0) {
        if (error != nullptr) {
            *error = "Cannot open /dev/urandom: " +
                     std::string{std::strerror(errno)};
        }
        return false;
    }
    std::size_t offset = 0;
    while (offset < output.size()) {
        const auto count =
            ::read(descriptor, output.data() + offset, output.size() - offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            const int code = errno;
            ::close(descriptor);
            if (error != nullptr) {
                *error = "Cannot read /dev/urandom: " +
                         std::string{std::strerror(code)};
            }
            return false;
        }
        offset += static_cast<std::size_t>(count);
    }
    if (::close(descriptor) != 0) {
        if (error != nullptr) {
            *error = "Cannot close /dev/urandom: " +
                     std::string{std::strerror(errno)};
        }
        return false;
    }
    return true;
#endif
}

} // namespace madoka::platform
