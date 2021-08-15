cmake_minimum_required(VERSION 3.11)
project(tests_crypto VERSION 0.0.2 LANGUAGES CXX)
    
add_executable(tests_crypto main.cpp)

target_link_libraries(tests_crypto
    PUBLIC
    bencrypto)
    
include(CTest)
