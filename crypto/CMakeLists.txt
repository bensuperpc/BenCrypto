cmake_minimum_required(VERSION 3.11)
project(bencrypto VERSION 0.0.2 LANGUAGES CXX)

add_library(bencrypto INTERFACE)
target_include_directories(bencrypto INTERFACE .)
