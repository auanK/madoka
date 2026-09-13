# =========================================================
# Madoka Test Suite Configuration
# =========================================================

function(madoka_add_test_suite target label)
    cmake_parse_arguments(
        ARG "" "" "SOURCES;LIBRARIES;DEFINITIONS" ${ARGN}
    )

    if(NOT ARG_SOURCES OR NOT ARG_LIBRARIES)
        message(
            FATAL_ERROR
            "${target} requires SOURCES and LIBRARIES"
        )
    endif()

    add_executable(
        ${target}
        ${ARG_SOURCES}
    )

    if(ARG_DEFINITIONS)
        target_compile_definitions(${target} PRIVATE ${ARG_DEFINITIONS})
    endif()

    if(MSVC)
        target_compile_options(${target} PRIVATE /UNDEBUG)
    else()
        target_compile_options(${target} PRIVATE -UNDEBUG)
    endif()

    target_link_libraries(
        ${target}
        PRIVATE
        ${ARG_LIBRARIES}
        madoka_warnings
    )

    target_include_directories(
        ${target}
        PRIVATE
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/src
    )

    add_test(
        NAME ${target}
        COMMAND ${target}
    )
    set_tests_properties(${target} PROPERTIES LABELS "${label}" TIMEOUT 60)
endfunction()

madoka_add_test_suite(
    test_config
    "unit.core.config"
    SOURCES
        unit/core/test_config.cpp
    LIBRARIES
        madoka_core
)

madoka_add_test_suite(
    test_protocol
    "unit.protocol"
    SOURCES
        unit/protocol/test_protocol.cpp
    LIBRARIES
        madoka_protocol
)

# ---------------------------------------------------------
# Unit Tests: Platform
# ---------------------------------------------------------
madoka_add_test_suite(
    test_tun
    "unit.platform.tun"
    SOURCES
        unit/platform/test_tun.cpp
    LIBRARIES
        madoka_platform
)

# ---------------------------------------------------------
# Unit Tests: Transport & TLS
# ---------------------------------------------------------
madoka_add_test_suite(
    test_transport
    "unit.transport"
    SOURCES
        unit/transport/test_transport.cpp
    LIBRARIES
        madoka_transport
)

madoka_add_test_suite(
    test_tls
    "unit.transport.tls"
    SOURCES
        unit/transport/test_tls.cpp
    LIBRARIES
        madoka_transport
        madoka_core
)

madoka_add_test_suite(
    test_invite
    "unit.security.invite"
    SOURCES
        unit/security/test_invite.cpp
    LIBRARIES
        madoka_security
        madoka_crypto
)

# ---------------------------------------------------------
# Unit Tests: Network
# ---------------------------------------------------------
madoka_add_test_suite(
    test_peer
    "unit.network.peer"
    SOURCES
        unit/network/test_peer.cpp
    LIBRARIES
        madoka_network
        madoka_core
)

madoka_add_test_suite(
    test_topology
    "unit.network.topology"
    SOURCES
        unit/network/test_topology.cpp
    LIBRARIES
        madoka_network
        madoka_core
)

madoka_add_test_suite(
    test_routing
    "unit.network.routing"
    SOURCES
        unit/network/test_routing.cpp
    LIBRARIES
        madoka_network
        madoka_core
)

madoka_add_test_suite(
    test_forwarding
    "unit.network.forwarding"
    SOURCES
        unit/network/test_forwarding.cpp
    LIBRARIES
        madoka_network
        madoka_core
)

madoka_add_test_suite(
    test_discovery
    "unit.network.discovery"
    SOURCES
        unit/network/test_discovery.cpp
    LIBRARIES
        madoka_network
        madoka_core
)

madoka_add_test_suite(
    test_distance_vector
    "unit.network.distance_vector"
    SOURCES
        unit/network/test_distance_vector.cpp
    LIBRARIES
        madoka_network
        madoka_core
)

madoka_add_test_suite(
    test_control_message
    "unit.network.control_message"
    SOURCES
        unit/network/test_control_message.cpp
    LIBRARIES
        madoka_network
        madoka_core
)

madoka_add_test_suite(
    test_serialization
    "unit.network.serialization"
    SOURCES
        unit/network/test_serialization.cpp
    LIBRARIES
        madoka_network
        madoka_core
)

madoka_add_test_suite(
    test_heartbeat
    "unit.network.heartbeat"
    SOURCES
        unit/network/test_heartbeat.cpp
    LIBRARIES
        madoka_network
        madoka_core
)

madoka_add_test_suite(
    test_data_packet
    "unit.network.data_packet"
    SOURCES
        unit/network/test_data_packet.cpp
    LIBRARIES
        madoka_network
        madoka_core
)

madoka_add_test_suite(
    test_kademlia
    "unit.network.kademlia"
    SOURCES
        unit/network/test_kademlia.cpp
    LIBRARIES
        madoka_network
        madoka_core
)

madoka_add_test_suite(
    test_join
    "unit.network.join"
    SOURCES
        unit/network/test_join.cpp
    LIBRARIES
        madoka_network
        madoka_core
)

# ---------------------------------------------------------
# Integration Tests
# ---------------------------------------------------------
madoka_add_test_suite(
    test_multihop
    "integration.multihop"
    SOURCES
        integration/test_multihop.cpp
    LIBRARIES
        madoka_network
        madoka_core
)

# ---------------------------------------------------------
# End-to-End Tests (Python)
# ---------------------------------------------------------
find_package(Python3 3.8 REQUIRED COMPONENTS Interpreter)

add_test(
    NAME lifecycle
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/e2e/smoke.py" "$<TARGET_FILE:madoka>"
)
set_tests_properties(lifecycle PROPERTIES LABELS "e2e.smoke" TIMEOUT 60)

add_test(
    NAME virtual_network
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/e2e/test_vnet.py" "$<TARGET_FILE:madoka>"
)
set_tests_properties(
    virtual_network
    PROPERTIES LABELS "e2e.vnet" TIMEOUT 60 SKIP_RETURN_CODE 77
)

add_test(
    NAME lab_3nodes
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/e2e/test_lab_3nodes.py" "$<TARGET_FILE:madoka>"
)
set_tests_properties(lab_3nodes PROPERTIES LABELS "e2e.lab_3nodes" TIMEOUT 60)

add_test(
    NAME zeroconfig
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/e2e/test_zeroconfig.py" "$<TARGET_FILE:madoka>"
)
set_tests_properties(zeroconfig PROPERTIES LABELS "e2e.zeroconfig" TIMEOUT 60)

# ---------------------------------------------------------
# Architecture Verification
# ---------------------------------------------------------
add_test(
    NAME madoka_architecture_dag
    COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/architecture/check_dependency_dag.cmake
)
set_tests_properties(madoka_architecture_dag PROPERTIES LABELS "architecture" TIMEOUT 30)
