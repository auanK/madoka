#ifndef MADOKA_CORE_DAEMON_HPP
#define MADOKA_CORE_DAEMON_HPP

namespace madoka {

struct AppState;

int daemon_run(AppState* app);

} // namespace madoka

#endif
