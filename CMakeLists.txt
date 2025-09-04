cmake_minimum_required(VERSION 3.20)
cmake_policy(SET CMP0167 NEW) 

project(WebSocketMessenger VERSION 1.1.0 DESCRIPTION "Lightweight WebSocket chat server" LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Packages
find_package(Boost 1.78 REQUIRED COMPONENTS system thread program_options)
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(spdlog REQUIRED)
find_package(utf8cpp CONFIG REQUIRED)

# Executable
add_executable(WebSocketServer src/server/main.cpp src/server/config.cpp src/server/logger.cpp)

# Warnings и Sanitizers
target_compile_options(WebSocketServer PRIVATE -Wall -Wextra -Wpedantic -Werror)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(WebSocketServer PRIVATE -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(WebSocketServer PRIVATE -fsanitize=address)
endif()

if(WIN32)
    target_compile_definitions(WebSocketServer PRIVATE _WIN32_WINNT=0x0601)
endif()

target_link_libraries(WebSocketServer PRIVATE
    Boost::system Boost::thread Boost::program_options
    OpenSSL::SSL OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    spdlog::spdlog
    utf8cpp::utf8cpp
)

if(WIN32)
    target_link_libraries(WebSocketServer PRIVATE ws2_32 mswsock crypt32)
endif()

# Static и Strip
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    if(WIN32)
        target_link_options(WebSocketServer PRIVATE -static-libgcc -static-libstdc++ -static)
    endif()
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        target_link_options(WebSocketServer PRIVATE -s)
    endif()
endif()

# Resources copy
if(EXISTS "${CMAKE_SOURCE_DIR}/src/web")
    add_custom_command(TARGET WebSocketServer POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory "${CMAKE_SOURCE_DIR}/src/web" "$<TARGET_FILE_DIR:WebSocketServer>/web"
    )
endif()
if(EXISTS "${CMAKE_SOURCE_DIR}/certs")
    add_custom_command(TARGET WebSocketServer POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory "${CMAKE_SOURCE_DIR}/certs" "$<TARGET_FILE_DIR:WebSocketServer>/certs"
    )
endif()

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(unit_tests
  src/tests/test_config.cpp
  src/tests/test_logger.cpp

  src/server/config.cpp
  src/server/logger.cpp
)

target_include_directories(unit_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_link_libraries(unit_tests PRIVATE
  GTest::gtest_main
  Boost::program_options
  spdlog::spdlog
  nlohmann_json::nlohmann_json
)

include(GoogleTest)
gtest_discover_tests(unit_tests)