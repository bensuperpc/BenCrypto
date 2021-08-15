#include <iostream>
#include "crypto_CRC32.hpp"

int main() {
    const std::string str = "Bonjour";
    const uint32_t CRC_VALUE = 0x6A0BC954;
    const uint32_t JAMCRC_VALUE = 0x95F436AB;
    const auto &&crc_stackoverflow = my::crypto::CRC32_StackOverflow((const unsigned char *)str.c_str(), str.length(), 0);
    const auto &&crc_1byte_tableless = my::crypto::CRC32_1byte_tableless(str.c_str(), str.length(), 0);
    const auto &&crc_1byte = my::crypto::CRC32_1byte(str.c_str(), str.length(), 0);
    const auto &&crc_bitwise = my::crypto::CRC32_bitwise(str.c_str(), str.length(), 0);
    const auto &&crc_halfbyte = my::crypto::CRC32_halfbyte(str.c_str(), str.length(), 0);
    
  std::cout << "Hello World!" << std::endl;
  return 0;
} 
