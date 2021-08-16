cmake_minimum_required(VERSION 3.11)
project(tests_crypto VERSION 0.0.2 LANGUAGES CXX)

set(CMAKE_MODULE_PATH
    ${CMAKE_MODULE_PATH}
    ${PROJECT_SOURCE_DIR}/cmake)

include(ConfigureBoost)
include(ConfigureOpenSSL)
    
add_executable(test_crypto_CRC test_crypto_CRC.cpp)
target_link_libraries(test_crypto_CRC
    PRIVATE
    bencrypto
    ${Boost_LIBRARIES}
    )

add_executable(test_crypto test_crypto.cpp)
target_link_libraries(test_crypto
    PRIVATE
    bencrypto
    ${Boost_LIBRARIES}
    ${OPENSSL_LIBRARIES}
    )

include(CTest)
