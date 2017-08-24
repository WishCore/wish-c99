project(wish)
cmake_minimum_required(VERSION 2.8.8)

set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})

FIND_PACKAGE(Git REQUIRED)

execute_process(COMMAND ${GIT_EXECUTABLE} describe --abbrev=0 --always --tags OUTPUT_VARIABLE EXECUTABLE_VERSION_STRING)
execute_process(COMMAND ${GIT_EXECUTABLE} describe --abbrev=4 --dirty --always --tags OUTPUT_VARIABLE WISH_CORE_VERSION_STRING)

string(REGEX REPLACE "\n$" "" EXECUTABLE_VERSION_STRING "${EXECUTABLE_VERSION_STRING}")
string(REGEX REPLACE "\n$" "" WISH_CORE_VERSION_STRING "${WISH_CORE_VERSION_STRING}")

set(EXECUTABLE "wish-core-${EXECUTABLE_VERSION_STRING}-x64-linux")
set(TEST_EXECUTABLE "test_bson")

#MESSAGE( STATUS "git-version: " ${EXECUTABLE_VERSION_STRING} )
#MESSAGE( STATUS "version: " ${WISH_CORE_VERSION_STRING} )
#MESSAGE( STATUS "output: " ${EXECUTABLE} )

add_definitions( "-DWISH_CORE_VERSION_STRING=\"${WISH_CORE_VERSION_STRING}\"") 

include_directories(src port/unix deps/bson deps/ed25519/src deps/mbedtls-2.1.2/include deps/uthash/include deps/wish-rpc-c99/src)

file(GLOB wish_SRC "src/*.c")
file(GLOB wish_port_SRC "port/unix/*.c")
file(GLOB_RECURSE wish_deps_SRC "deps/bson/*.c" "deps/ed25519/src/*.c" "deps/mbedtls-2.1.2/library/*.c" "deps/uthash/src/*.c" "deps/wish-rpc-c99/src/*.c")

list(REMOVE_ITEM wish_port_SRC "${CMAKE_SOURCE_DIR}/port/unix/test_bson.c")

file(GLOB wish_port_test_SRC "port/unix/test_bson.c" "port/unix/fs_port.c" "src/wish_debug.c" "src/wish_platform.c" "src/wish_fs.c")
list(REMOVE_ITEM wish_port_test_SRC "${CMAKE_SOURCE_DIR}/port/unix/app.c")

#MESSAGE( STATUS "wish_SRC: " ${wish_SRC} )
#MESSAGE( STATUS "wish_port_SRC: " ${wish_port_SRC} )

add_executable(${EXECUTABLE} ${wish_SRC} ${wish_port_SRC} ${wish_deps_SRC})
#add_executable(${TEST_EXECUTABLE} ${wish_port_test_SRC} ${wish_deps_SRC})

#enable_testing()

#add_test(NAME bson_test COMMAND ${TEST_EXECUTABLE})
