#ifndef MADOKA_PLATFORM_RANDOM_HPP
#define MADOKA_PLATFORM_RANDOM_HPP

#include <cstdint>
#include <span>
#include <string>

namespace madoka::platform {

bool random_bytes(std::span<uint8_t> output, std::string* error = nullptr);

} // namespace madoka::platform

#endif
