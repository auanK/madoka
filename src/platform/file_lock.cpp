#include "platform/file_lock.hpp"

#include "platform/private_storage.hpp"

#include <cerrno>
#include <system_error>
#include <utility>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace madoka::platform {

void file_lock_release(std::intptr_t* handle) noexcept {
    if (handle == nullptr || *handle == invalid_file_lock) {
        return;
    }
    const auto value = std::exchange(*handle, invalid_file_lock);
#ifdef _WIN32
    CloseHandle(reinterpret_cast<HANDLE>(value));
#else
    ::close(static_cast<int>(value));
#endif
}

bool file_lock_acquire(const std::filesystem::path& path,
                       std::intptr_t* handle,
                       std::string* error) {
    if (handle == nullptr || path.empty() || path.parent_path().empty()) {
        if (error != nullptr) {
            *error = "Invalid lock path";
        }
        return false;
    }
    file_lock_release(handle);
    std::error_code exists_error;
    const bool exists = std::filesystem::exists(path, exists_error);
    if (exists_error || (exists ? !private_protect_file(path, error)
                                : !private_write_atomically(path, {}, error))) {
        if (error != nullptr && error->empty()) {
            *error = "Cannot prepare state lock";
        }
        return false;
    }
#ifdef _WIN32
    const HANDLE file =
        CreateFileW(path.c_str(),
                    GENERIC_READ,
                    0,
                    nullptr,
                    OPEN_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                    nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        if (error != nullptr) {
            *error = GetLastError() == ERROR_SHARING_VIOLATION
                         ? "State is already in use by another process"
                         : "Cannot acquire state lock";
        }
        return false;
    }
    *handle = reinterpret_cast<std::intptr_t>(file);
#else
    int flags = O_RDONLY | O_CREAT;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int file = ::open(path.c_str(), flags, 0600);
    if (file < 0 || ::flock(file, LOCK_EX | LOCK_NB) != 0) {
        if (file >= 0) {
            ::close(file);
        }
        if (error != nullptr) {
            *error = "State is already in use by another process";
        }
        return false;
    }
    *handle = file;
#endif
    return true;
}

} // namespace madoka::platform
