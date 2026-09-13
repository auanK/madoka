#ifndef MADOKA_PROTOCOL_CODEC_HPP
#define MADOKA_PROTOCOL_CODEC_HPP

#include "protocol/message.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace madoka {

bool message_validate(const Message& msg, std::string* error = nullptr);

std::vector<uint8_t> message_encode(const Message& msg,
                                    std::string* error = nullptr);

bool message_decode(std::span<const uint8_t> bytes,
                    Message* out_msg,
                    std::string* error = nullptr);

std::optional<std::size_t> message_peek_size(std::span<const uint8_t> bytes,
                                             std::string* error = nullptr);

} // namespace madoka

#endif
