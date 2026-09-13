cmake_minimum_required(VERSION 3.28)

if(NOT DEFINED PROJECT_SOURCE_DIR)
    message(FATAL_ERROR "PROJECT_SOURCE_DIR is required")
endif()

function(assert_tree_excludes root pattern reason)
    file(GLOB_RECURSE files LIST_DIRECTORIES false
        "${PROJECT_SOURCE_DIR}/${root}/*.c"
        "${PROJECT_SOURCE_DIR}/${root}/*.cpp"
        "${PROJECT_SOURCE_DIR}/${root}/*.h"
        "${PROJECT_SOURCE_DIR}/${root}/*.hpp")
    foreach(path IN LISTS files)
        file(READ "${path}" text)
        if(text MATCHES "${pattern}")
            file(RELATIVE_PATH relative "${PROJECT_SOURCE_DIR}" "${path}")
            message(FATAL_ERROR "${reason}: ${relative}")
        endif()
    endforeach()
endfunction()

function(assert_file_excludes path pattern reason)
    file(READ "${PROJECT_SOURCE_DIR}/${path}" text)
    if(text MATCHES "${pattern}")
        message(FATAL_ERROR "${reason}: ${path}")
    endif()
endfunction()

function(assert_no_includes root forbidden)
    assert_tree_excludes(
        "${root}"
        "#include[ \t]+[\"<](${forbidden})/"
        "forbidden dependency include")
endfunction()

# Architecture layer boundary enforcement
assert_no_includes(include/protocol "network|transport|core|platform")
assert_no_includes(src/protocol "network|transport|core|platform")
assert_no_includes(include/crypto "network|transport")

message(STATUS "Madoka architecture DAG verification passed.")
