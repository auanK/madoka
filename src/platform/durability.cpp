#include "platform/durability.hpp"

#include <cerrno>
#include <cstring>
#include <system_error>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace madoka::platform {
namespace {

bool regular_file(const std::filesystem::path& path, std::string* error) {
    std::error_code code;
    const auto status = std::filesystem::symlink_status(path, code);
    if (code || std::filesystem::is_symlink(status) ||
        !std::filesystem::is_regular_file(status)) {
        if (error != nullptr) {
            *error = "Expected a regular file: " + path.string();
        }
        return false;
    }
    return true;
}

} // namespace

bool sync_file(const std::filesystem::path& path, std::string* error) {
    if (!regular_file(path, error)) {
        return false;
    }
#ifdef _WIN32
    const HANDLE file = CreateFileW(path.c_str(),
                                    GENERIC_READ | GENERIC_WRITE,
                                    FILE_SHARE_READ,
                                    nullptr,
                                    OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL,
                                    nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        if (error != nullptr) {
            *error = "Cannot open file for durable flush: " + path.string();
        }
        return false;
    }
    const bool flushed = FlushFileBuffers(file) != 0;
    const DWORD code = flushed ? ERROR_SUCCESS : GetLastError();
    CloseHandle(file);
    if (!flushed && error != nullptr) {
        *error = "FlushFileBuffers failed: " + std::to_string(code);
    }
    return flushed;
#else
    int flags = O_RDONLY;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int file = ::open(path.c_str(), flags);
    if (file < 0) {
        if (error != nullptr) {
            *error = "Cannot open file for durable flush: " +
                     std::string{std::strerror(errno)};
        }
        return false;
    }
    int result = 0;
    do {
        result = ::fsync(file);
    } while (result != 0 && errno == EINTR);
    const int code = errno;
    ::close(file);
    if (result != 0 && error != nullptr) {
        *error = "fsync failed: " + std::string{std::strerror(code)};
    }
    return result == 0;
#endif
}

bool sync_parent_directory(const std::filesystem::path& path,
                           std::string* error) {
#ifdef _WIN32
    (void)path;
    (void)error;
    return true;
#else
    int flags = O_RDONLY;
#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int directory = ::open(path.parent_path().c_str(), flags);
    if (directory < 0) {
        if (error != nullptr) {
            *error = "Cannot open parent directory for durable flush: " +
                     std::string{std::strerror(errno)};
        }
        return false;
    }
    int result = 0;
    do {
        result = ::fsync(directory);
    } while (result != 0 && errno == EINTR);
    const int code = errno;
    ::close(directory);
    if (result != 0 && error != nullptr) {
        *error = "Directory fsync failed: " + std::string{std::strerror(code)};
    }
    return result == 0;
#endif
}

bool replace_atomically(const std::filesystem::path& source,
                        const std::filesystem::path& target,
                        std::string* error) {
    if (source.parent_path().lexically_normal() !=
            target.parent_path().lexically_normal() ||
        !regular_file(source, error)) {
        if (error != nullptr && error->empty()) {
            *error = "Atomic replacement requires sibling paths";
        }
        return false;
    }
    std::error_code target_error;
    const auto target_status =
        std::filesystem::symlink_status(target, target_error);
    if (!target_error && (std::filesystem::is_symlink(target_status) ||
                          std::filesystem::is_directory(target_status))) {
        if (error != nullptr) {
            *error = "Atomic replacement target is not a regular file";
        }
        return false;
    }
    if (target_error && target_error != std::errc::no_such_file_or_directory) {
        if (error != nullptr) {
            *error = "Cannot inspect atomic replacement target: " +
                     target_error.message();
        }
        return false;
    }
#ifdef _WIN32
    if (MoveFileExW(source.c_str(),
                    target.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
        if (error != nullptr) {
            *error =
                "Atomic replacement failed: " + std::to_string(GetLastError());
        }
        return false;
    }
#else
    std::error_code code;
    std::filesystem::rename(source, target, code);
    if (code) {
        if (error != nullptr) {
            *error = "Atomic replacement failed: " + code.message();
        }
        return false;
    }
#endif
    return true;
}

} // namespace madoka::platform
