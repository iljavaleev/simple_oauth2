cmake_minimum_required(VERSION 3.5)

project(res)

set(CMAKE_CXX_COMPILER "/usr/bin/g++")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")


find_package(nlohmann_json 3.11.3 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Crow REQUIRED)
find_package(Threads REQUIRED)
find_package(mongocxx REQUIRED)
find_package(bsoncxx REQUIRED)

include_directories(/usr/local/include /opt/homebrew/include/ ${OPENSSL_INCLUDE_DIR})

add_executable(res main.cpp Handlers.cpp DB.cpp)
target_link_libraries(res Crow::Crow nlohmann_json::nlohmann_json  mongo::mongocxx_shared mongo::bsoncxx_shared ${CMAKE_THREAD_LIBS_INIT} ${OPENSSL_LIBRARIES})
 