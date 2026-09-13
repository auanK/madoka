#ifndef MADOKA_PLATFORM_DURABILITY_HPP
#define MADOKA_PLATFORM_DURABILITY_HPP

#include <filesystem>
#include <string>

namespace madoka::platform {

bool sync_file(const std::filesystem::path& path, std::string* error = nullptr);

bool sync_parent_directory(const std::filesystem::path& path,
                           std::string* error = nullptr);

bool replace_atomically(const std::filesystem::path& source,
                        const std::filesystem::path& target,
                        std::string* error = nullptr);

} // namespace madoka::platform

#endif
