cmake_minimum_required(VERSION 3.5)

project(res)

set(CMAKE_CXX_COMPILER "/usr/bin/g++")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
set(BOOST_ENABLE_CMAKE ON)

find_package(nlohmann_json 3.11.3 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(Boost REQUIRED system)
find_package(mongocxx REQUIRED)
find_package(bsoncxx REQUIRED)
find_package(cpr REQUIRED)
find_package(jwt-cpp CONFIG REQUIRED)

include_directories(/usr/local/include  ${Boost_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR})

add_executable(res main.cpp Handlers.cpp DB.cpp Utils.cpp)
target_link_libraries(res cpr::cpr jwt-cpp::jwt-cpp nlohmann_json::nlohmann_json  mongo::mongocxx_shared mongo::bsoncxx_shared ${CMAKE_THREAD_LIBS_INIT} ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES})
 