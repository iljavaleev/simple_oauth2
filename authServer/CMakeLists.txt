cmake_minimum_required(VERSION 3.5)

project(auth)

set(CMAKE_CXX_COMPILER "/usr/bin/g++")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
set(Boost_USE_MULTITHREADED ON)  
set(TREADS_PREFER_PTHREAD_FLAG ON)

find_package(nlohmann_json 3.11.3 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Crow REQUIRED)
find_package(Threads REQUIRED)
find_package(CURL)
find_package(mongocxx REQUIRED)
find_package(bsoncxx REQUIRED)
find_package(inja REQUIRED)
add_library(inja INTERFACE)

include_directories(/usr/local/include ${Boost_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR})

add_executable(auth DB.cpp Handlers.cpp Utils.cpp main.cpp)

target_link_libraries(auth ${PQXX_LIB} Crow::Crow nlohmann_json::nlohmann_json mongo::mongocxx_shared mongo::bsoncxx_shared cpr::cpr inja ${CMAKE_THREAD_LIBS_INIT} ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES})

