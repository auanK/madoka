#ifndef MADOKA_PLATFORM_PRIVATE_STORAGE_HPP
#define MADOKA_PLATFORM_PRIVATE_STORAGE_HPP

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>

namespace madoka::platform {

bool private_ensure_directory(const std::filesystem::path& path,
                              std::string* error = nullptr);

bool private_protect_file(const std::filesystem::path& path,
                          std::string* error = nullptr);

bool private_write_atomically(const std::filesystem::path& path,
                              std::string_view bytes,
                              std::string* error = nullptr);

bool private_read_file(const std::filesystem::path& path,
                       std::size_t maximum_size,
                       std::string* contents,
                       std::string* error = nullptr);

} // namespace madoka::platform

#endif
