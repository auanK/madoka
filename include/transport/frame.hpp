#ifndef MADOKA_TRANSPORT_FRAME_HPP
#define MADOKA_TRANSPORT_FRAME_HPP

#include <cstddef>

namespace madoka {

constexpr std::size_t MAX_RECV_BUFFER_SIZE = 8192;

constexpr std::size_t RECV_CHUNK_SIZE = 1024;

} // namespace madoka

#endif
