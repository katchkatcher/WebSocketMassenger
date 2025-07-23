cmake_minimum_required(VERSION 3.16)

# Устанавливаем политику для Boost
cmake_policy(SET CMP0167 NEW)

project(WebSocketMassenger VERSION 1.0.0 LANGUAGES CXX)

# Стандарт C++
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Настройки сборки
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Windows специфика
if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0601)
endif()

# Пакеты
find_package(Boost REQUIRED COMPONENTS system thread)
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json REQUIRED)

# Основное приложение
add_executable(WebSocketServer src/server/main.cpp)

# Подключение библиотек
target_link_libraries(WebSocketServer PRIVATE
    Boost::system
    Boost::thread
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
)

# Windows дополнительные библиотеки
if(WIN32)
    target_link_libraries(WebSocketServer PRIVATE
        # базовые сетевые функции
        ws2_32  
        # асинхронные операции
        mswsock
        # криптографические функции
        crypt32
    )
endif()

# Статическая линковка
if(WIN32 AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_link_options(WebSocketServer PRIVATE 
        -static-libgcc 
        -static-libstdc++
        -static
    )
endif()

# Strip в Release
if(CMAKE_BUILD_TYPE STREQUAL "Release" AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_link_options(WebSocketServer PRIVATE -s)
endif()

# Копирование ресурсов
if(EXISTS "${CMAKE_SOURCE_DIR}/src/web")
    add_custom_command(TARGET WebSocketServer POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_SOURCE_DIR}/src/web"
            "$<TARGET_FILE_DIR:WebSocketServer>/web"
    )
endif()

if(EXISTS "${CMAKE_SOURCE_DIR}/certs")
    add_custom_command(TARGET WebSocketServer POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_SOURCE_DIR}/certs"
            "$<TARGET_FILE_DIR:WebSocketServer>/certs"
    )
endif()