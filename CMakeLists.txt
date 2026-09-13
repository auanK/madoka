cmake_minimum_required(VERSION 3.28)

project(madoka VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

include(CTest)

# =========================================================
# Compiler Warnings Target
# =========================================================
add_library(madoka_warnings INTERFACE)
if(WIN32)
    add_compile_definitions(NOMINMAX _CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN)
    if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
        add_compile_options(/bigobj)
    endif()
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    target_compile_options(madoka_warnings INTERFACE
        $<$<COMPILE_LANGUAGE:CXX>:/W4>
        $<$<COMPILE_LANGUAGE:CXX>:/permissive->
        $<$<COMPILE_LANGUAGE:CXX>:/utf-8>
    )
else()
    target_compile_options(madoka_warnings INTERFACE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wsign-conversion
        -Wshadow
        -Wno-missing-field-initializers
    )
endif()

# =========================================================
# Release Optimizations Target
# =========================================================
add_library(madoka_release_optimizations INTERFACE)
if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    target_compile_options(madoka_release_optimizations INTERFACE
        $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:/O2 /Gy /Gw>
    )
    target_link_options(madoka_release_optimizations INTERFACE
        $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:/OPT:REF /OPT:ICF>
    )
else()
    target_compile_options(madoka_release_optimizations INTERFACE
        $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:-O2 -ffunction-sections -fdata-sections>
    )
    target_link_options(madoka_release_optimizations INTERFACE
        $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:-Wl,--gc-sections -s>
    )
endif()

# =========================================================
# Security & Hardening Target
# =========================================================
add_library(madoka_hardening INTERFACE)
if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    target_compile_options(madoka_hardening INTERFACE
        /GS
    )
    target_link_options(madoka_hardening INTERFACE
        /DYNAMICBASE
        /NXCOMPAT
        /HIGHENTROPYVA
    )
else()
    include(CheckCXXCompilerFlag)
    include(CheckLinkerFlag)
    include(CheckCXXSourceCompiles)

    check_cxx_compiler_flag("-fstack-protector-strong" MADOKA_HAS_STACK_PROTECTOR_STRONG)
    if(MADOKA_HAS_STACK_PROTECTOR_STRONG)
        target_compile_options(madoka_hardening INTERFACE -fstack-protector-strong)
    endif()

    if(WIN32)
        check_linker_flag(CXX "-Wl,--dynamicbase" MADOKA_HAS_DYNAMICBASE)
        if(MADOKA_HAS_DYNAMICBASE)
            target_link_options(madoka_hardening INTERFACE
                -Wl,--dynamicbase
                -Wl,--nxcompat
                -Wl,--high-entropy-va
            )
        endif()
    else()
        set(CMAKE_REQUIRED_FLAGS_SAVE "${CMAKE_REQUIRED_FLAGS}")
        set(CMAKE_REQUIRED_FLAGS "-O2")
        check_cxx_source_compiles("
            #define _FORTIFY_SOURCE 3
            #include <string.h>
            int main() { return 0; }
        " MADOKA_HAS_FORTIFY_SOURCE_3)
        if(MADOKA_HAS_FORTIFY_SOURCE_3)
            target_compile_definitions(madoka_hardening INTERFACE
                $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:_FORTIFY_SOURCE=3>
            )
        else()
            check_cxx_source_compiles("
                #define _FORTIFY_SOURCE 2
                #include <string.h>
                int main() { return 0; }
            " MADOKA_HAS_FORTIFY_SOURCE_2)
            if(MADOKA_HAS_FORTIFY_SOURCE_2)
                target_compile_definitions(madoka_hardening INTERFACE
                    $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:_FORTIFY_SOURCE=2>
                )
            endif()
        endif()
        set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS_SAVE}")

        check_linker_flag(CXX "-Wl,-z,relro" MADOKA_HAS_RELRO)
        if(MADOKA_HAS_RELRO)
            target_link_options(madoka_hardening INTERFACE -Wl,-z,relro)
        endif()

        check_linker_flag(CXX "-Wl,-z,now" MADOKA_HAS_BIND_NOW)
        if(MADOKA_HAS_BIND_NOW)
            target_link_options(madoka_hardening INTERFACE -Wl,-z,now)
        endif()
    endif()
endif()

# =========================================================
# External Dependencies
# =========================================================
find_package(Threads REQUIRED)

if(WIN32)
    set(OPENSSL_USE_STATIC_LIBS ON)
else()
    set(OPENSSL_USE_STATIC_LIBS OFF)
endif()
find_package(OpenSSL REQUIRED)

set(MADOKA_PLATFORM_LIBS)
if(WIN32)
    list(APPEND MADOKA_PLATFORM_LIBS
        ws2_32 advapi32 bcrypt shell32 iphlpapi crypt32)
endif()

# =========================================================
# 0. Config Module
# =========================================================
add_library(madoka_config STATIC
    src/core/config.cpp
)
target_include_directories(madoka_config
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
    PRIVATE
        ${PROJECT_SOURCE_DIR}/src
)
target_link_libraries(madoka_config
    PUBLIC
        ${MADOKA_PLATFORM_LIBS}
    PRIVATE
        madoka_warnings
        madoka_release_optimizations
        madoka_hardening
)

# =========================================================
# 1. Platform Module (Sockets, Wintun / Linux TUN)
# =========================================================
add_library(madoka_platform STATIC
    src/platform/durability.cpp
    src/platform/file_lock.cpp
    src/platform/private_storage.cpp
    src/platform/random.cpp
    src/platform/socket.cpp
    src/platform/tun.cpp
)
target_include_directories(madoka_platform
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
    PRIVATE
        ${PROJECT_SOURCE_DIR}/src
)
target_link_libraries(madoka_platform
    PUBLIC
        ${MADOKA_PLATFORM_LIBS}
    PRIVATE
        madoka_warnings
        madoka_release_optimizations
        madoka_hardening
)

# =========================================================
# 2. Crypto Module
# =========================================================
add_library(madoka_crypto STATIC
    src/crypto/identity.cpp
    src/crypto/tls.cpp
)
target_include_directories(madoka_crypto
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
    PRIVATE
        ${PROJECT_SOURCE_DIR}/src
)
target_link_libraries(madoka_crypto
    PUBLIC
        madoka_config
        madoka_platform
        OpenSSL::Crypto
        OpenSSL::SSL
    PRIVATE
        madoka_warnings
        madoka_release_optimizations
        madoka_hardening
        ${MADOKA_PLATFORM_LIBS}
)

# =========================================================
# 3. Security State
# =========================================================
add_library(madoka_security STATIC
    src/security/invite.cpp
)
target_include_directories(madoka_security
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)
target_link_libraries(madoka_security
    PUBLIC
        madoka_config
        madoka_platform
        OpenSSL::Crypto
    PRIVATE
        madoka_warnings
        madoka_release_optimizations
        madoka_hardening
)

# =========================================================
# 4. Protocol Module
# =========================================================
add_library(madoka_protocol STATIC
    src/protocol/codec.cpp
)
target_include_directories(madoka_protocol
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
    PRIVATE
        ${PROJECT_SOURCE_DIR}/src
)
target_link_libraries(madoka_protocol
    PUBLIC
        madoka_crypto
    PRIVATE
        madoka_warnings
        madoka_release_optimizations
        madoka_hardening
)

# =========================================================
# 5. Transport Module
# =========================================================
add_library(madoka_transport STATIC
    src/transport/session.cpp
)
target_include_directories(madoka_transport
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
    PRIVATE
        ${PROJECT_SOURCE_DIR}/src
)
target_link_libraries(madoka_transport
    PUBLIC
        madoka_crypto
        madoka_platform
        madoka_protocol
    PRIVATE
        madoka_warnings
        madoka_release_optimizations
        madoka_hardening
)

# =========================================================
# 6. Network Module
# =========================================================
add_library(madoka_network STATIC
    src/network/peer.cpp
    src/network/topology.cpp
    src/network/route.cpp
    src/network/routing.cpp
    src/network/forwarding.cpp
    src/network/discovery.cpp
    src/network/distance_vector.cpp
    src/network/control_message.cpp
    src/network/serialization.cpp
    src/network/heartbeat.cpp
    src/network/data_packet.cpp
    src/network/data_serialization.cpp
    src/network/route_advertisement.cpp
    src/network/node_state.cpp
    src/network/kademlia.cpp
    src/network/join.cpp
)
target_include_directories(madoka_network
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
    PRIVATE
        ${PROJECT_SOURCE_DIR}/src
)
target_link_libraries(madoka_network
    PUBLIC
        madoka_crypto
        madoka_protocol
        madoka_transport
    PRIVATE
        madoka_warnings
        madoka_release_optimizations
        madoka_hardening
)

# =========================================================
# 7. Core Module
# =========================================================
add_library(madoka_core STATIC
    src/core/daemon.cpp
    src/core/lifecycle.cpp
    src/core/app.cpp
)
target_include_directories(madoka_core
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
    PRIVATE
        ${PROJECT_SOURCE_DIR}/src
)
target_link_libraries(madoka_core
    PUBLIC
        madoka_config
        madoka_network
        madoka_transport
        madoka_platform
        madoka_crypto
        madoka_security
        Threads::Threads
    PRIVATE
        madoka_warnings
        madoka_release_optimizations
        madoka_hardening
)

# =========================================================
# Main Daemon Executable
# =========================================================
add_executable(madoka src/main.cpp)
target_include_directories(madoka
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/src
)
target_link_libraries(madoka
    PRIVATE
        madoka_core
        madoka_warnings
        madoka_release_optimizations
        madoka_hardening
)
if(MINGW)
    target_link_options(madoka PRIVATE
        $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:-static>
    )
endif()

if(WIN32)
    if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
        message(FATAL_ERROR "The bundled Wintun driver supports Windows x64 only")
    endif()

    set(MADOKA_WINTUN_DLL
        "${PROJECT_SOURCE_DIR}/third_party/wintun/bin/amd64/wintun.dll")
    if(NOT EXISTS "${MADOKA_WINTUN_DLL}")
        message(FATAL_ERROR "Missing bundled Wintun DLL: ${MADOKA_WINTUN_DLL}")
    endif()

    add_custom_command(
        TARGET madoka POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${MADOKA_WINTUN_DLL}"
            "$<TARGET_FILE_DIR:madoka>/wintun.dll"
        COMMENT "Copying Wintun next to madoka"
        VERBATIM
    )
endif()

# =========================================================
# Link-Time Optimization & PIC
# =========================================================
set(MADOKA_FIRST_PARTY_TARGETS
    madoka_config
    madoka_crypto
    madoka_platform
    madoka_security
    madoka_protocol
    madoka_transport
    madoka_network
    madoka_core
    madoka
)

set_target_properties(${MADOKA_FIRST_PARTY_TARGETS} PROPERTIES POSITION_INDEPENDENT_CODE TRUE)

include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported)
if(ipo_supported AND NOT (CMAKE_CXX_COMPILER_ID MATCHES "GNU" AND WIN32))
    set_target_properties(${MADOKA_FIRST_PARTY_TARGETS} PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

include(GNUInstallDirs)
install(
    TARGETS madoka
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT madoka
)
if(WIN32)
    install(
        FILES "${MADOKA_WINTUN_DLL}"
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT madoka
    )
endif()

# =========================================================
# Test Suites
# =========================================================
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

# =========================================================
# Formatting and Style Tooling
# =========================================================
find_program(CLANG_FORMAT_BIN NAMES clang-format)
if(CLANG_FORMAT_BIN)
    message(STATUS "clang-format found: ${CLANG_FORMAT_BIN}")
    file(GLOB_RECURSE ALL_CXX_SOURCE_FILES
        ${PROJECT_SOURCE_DIR}/include/*.hpp
        ${PROJECT_SOURCE_DIR}/src/*.cpp
        ${PROJECT_SOURCE_DIR}/tests/*.cpp
    )

    add_custom_target(
        format
        COMMAND ${CLANG_FORMAT_BIN} -i --style=file ${ALL_CXX_SOURCE_FILES}
        COMMENT "Formatting codebase with clang-format..."
    )

    add_custom_target(
        check-format
        COMMAND ${CLANG_FORMAT_BIN} --dry-run --Werror --style=file ${ALL_CXX_SOURCE_FILES}
        COMMENT "Verifying code formatting with clang-format..."
    )
endif()
