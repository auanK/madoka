#ifndef MADOKA_CORE_LIFECYCLE_HPP
#define MADOKA_CORE_LIFECYCLE_HPP

#include <string>

namespace madoka::core {

bool lifecycle_install_signals(std::string* error = nullptr);

bool lifecycle_is_stop_requested();

void lifecycle_request_stop();

} // namespace madoka::core

#endif
