project(wish)
cmake_minimum_required(VERSION 2.8.8)

#set(CMAKE_C_FLAGS "-Wall -std=c99 -Wno-pointer-sign")
set(CMAKE_C_FLAGS "-Wall -m32 -Wno-pointer-sign -Wno-unused-variable")
#set(CMAKE_C_FLAGS "-Wall -Wno-pointer-sign -Wno-unused-variable")
#set(CMAKE_C_FLAGS_RELEASE "-Os -O3")
#set(CMAKE_C_FLAGS_DEBUG "-O0 -g")

set(CMAKE_BINARY_DIR ${CMAKE_SOURCE_DIR}/build)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})

FIND_PACKAGE(Git REQUIRED)

execute_process(COMMAND ${GIT_EXECUTABLE} describe --abbrev=0 --always --tags OUTPUT_VARIABLE EXECUTABLE_VERSION_STRING)
execute_process(COMMAND ${GIT_EXECUTABLE} describe --abbrev=4 --dirty --always --tags OUTPUT_VARIABLE WISH_CORE_VERSION_STRING)

string(REGEX REPLACE "\n$" "" EXECUTABLE_VERSION_STRING "${EXECUTABLE_VERSION_STRING}")
string(REGEX REPLACE "\n$" "" WISH_CORE_VERSION_STRING "${WISH_CORE_VERSION_STRING}")

set(EXECUTABLE "wish-core-${EXECUTABLE_VERSION_STRING}-x64-linux")
set(TEST_EXECUTABLE1 "test_bson")
set(TEST_EXECUTABLE2 "test_bson_update")

#MESSAGE( STATUS "git-version: " ${EXECUTABLE_VERSION_STRING} )
#MESSAGE( STATUS "version: " ${WISH_CORE_VERSION_STRING} )
#MESSAGE( STATUS "output: " ${EXECUTABLE} )

add_definitions( "-DWISH_CORE_VERSION_STRING=\"${WISH_CORE_VERSION_STRING}\"") 
add_definitions( "-DWLD_META_PRODUCT=\"${WLD_META_PRODUCT}\"") 

include_directories(src port/unix deps/bson deps/ed25519/src deps/mbedtls-2.1.2/include deps/uthash/include deps/wish-rpc-c99/src)

file(GLOB wish_SRC "src/*.c")
file(GLOB wish_port_SRC "port/unix/*.c")
file(GLOB_RECURSE wish_deps_SRC "deps/bson/*.c" "deps/ed25519/src/*.c" "deps/mbedtls-2.1.2/library/*.c" "deps/uthash/src/*.c" "deps/wish-rpc-c99/src/*.c")

list(REMOVE_ITEM wish_port_SRC "${CMAKE_SOURCE_DIR}/port/unix/test_bson.c")
list(REMOVE_ITEM wish_port_SRC "${CMAKE_SOURCE_DIR}/port/unix/test_bson_update.c")

file(GLOB wish_port_test1_SRC "port/unix/test_bson.c" "port/unix/fs_port.c" "src/wish_debug.c" "src/wish_platform.c" "src/wish_fs.c")
file(GLOB wish_port_test2_SRC "port/unix/test_bson_update.c" "port/unix/fs_port.c" "src/wish_debug.c" "src/wish_platform.c" "src/wish_fs.c")
list(REMOVE_ITEM wish_port_test1_SRC "${CMAKE_SOURCE_DIR}/port/unix/app.c")
list(REMOVE_ITEM wish_port_test2_SRC "${CMAKE_SOURCE_DIR}/port/unix/app.c")

#MESSAGE( STATUS "wish_SRC: " ${wish_SRC} )
#MESSAGE( STATUS "wish_port_SRC: " ${wish_port_SRC} )

add_executable(${EXECUTABLE} ${wish_SRC} ${wish_port_SRC} ${wish_deps_SRC})
#add_executable(${TEST_EXECUTABLE1} ${wish_port_test1_SRC} ${wish_deps_SRC})
#add_executable(${TEST_EXECUTABLE2} ${wish_port_test2_SRC} ${wish_deps_SRC})

#enable_testing()

#add_test(NAME bson_test COMMAND ${TEST_EXECUTABLE})
