cmake_minimum_required(VERSION 3.11)
project(my_crypto VERSION 0.0.2 LANGUAGES CXX)

add_subdirectory ("crypto")

option(ENABLE_TESTING ON)

if (ENABLE_TESTING)
    enable_testing()
    add_subdirectory("tests")
endif()
