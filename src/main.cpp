#include "core/app.hpp"

#include <iostream>

int main(int argc, char* argv[]) {
    madoka::AppState app{};
    std::string error;

    if (!madoka::app_init(&app, argc, argv, &error)) {
        std::cerr << "Initialization error: " << error << '\n';
        return 1;
    }

    return madoka::app_run(&app);
}
