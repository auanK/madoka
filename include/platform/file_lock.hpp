#ifndef MADOKA_PLATFORM_FILE_LOCK_HPP
#define MADOKA_PLATFORM_FILE_LOCK_HPP

#include <cstdint>
#include <filesystem>
#include <string>

namespace madoka::platform {

inline constexpr std::intptr_t invalid_file_lock = -1;

bool file_lock_acquire(const std::filesystem::path& path,
                       std::intptr_t* handle,
                       std::string* error = nullptr);

void file_lock_release(std::intptr_t* handle) noexcept;

} // namespace madoka::platform

#endif
