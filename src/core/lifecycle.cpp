#include "core/lifecycle.hpp"

#include <atomic>
#include <csignal>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace madoka::core {

namespace {
std::atomic_flag g_stop_requested{};

void signal_handler(int) noexcept {
    g_stop_requested.test_and_set(std::memory_order_relaxed);
}

#ifdef _WIN32
BOOL WINAPI console_ctrl_handler(DWORD ctrl_type) {
    switch (ctrl_type) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            g_stop_requested.test_and_set(std::memory_order_relaxed);
            return TRUE;
        default:
            return FALSE;
    }
}
#endif
} // namespace

bool lifecycle_install_signals(std::string* error) {
    constexpr int signals[] = {
        SIGINT,
        SIGTERM,
#ifdef _WIN32
        SIGBREAK,
#endif
    };
    for (const int signal : signals) {
        if (std::signal(signal, signal_handler) == SIG_ERR) {
            if (error)
                *error = "Could not register shutdown signal handlers.";
            return false;
        }
    }
#ifdef _WIN32
    if (!SetConsoleCtrlHandler(console_ctrl_handler, TRUE)) {
        if (error)
            *error = "Could not register console control handler.";
        return false;
    }
#endif
    return true;
}

bool lifecycle_is_stop_requested() {
    return g_stop_requested.test(std::memory_order_relaxed);
}

void lifecycle_request_stop() {
    g_stop_requested.test_and_set(std::memory_order_relaxed);
}

} // namespace madoka::core
