//////////////////////////////////////////////////////////////
//   ____                                                   //
//  | __ )  ___ _ __  ___ _   _ _ __   ___ _ __ _ __   ___  //
//  |  _ \ / _ \ '_ \/ __| | | | '_ \ / _ \ '__| '_ \ / __| //
//  | |_) |  __/ | | \__ \ |_| | |_) |  __/ |  | |_) | (__  //
//  |____/ \___|_| |_|___/\__,_| .__/ \___|_|  | .__/ \___| //
//                             |_|             |_|          //
//////////////////////////////////////////////////////////////
//                                                          //
//  BenLib, 2021                                            //
//  Created: 04, March, 2021                                //
//  Modified: 04, March, 2021                               //
//  file: crypto.cpp                                        //
//  Crypto                                                  //
//  Source:
//  http://stackoverflow.com/questions/8710719/generating-an-alphabetic-sequence-in-java
//  //
//          https://github.com/theo546/stuff //
//          https://stackoverflow.com/a/19299611/10152334 //
//          https://gms.tf/stdfind-and-memchr-optimizations.html //
//          https://medium.com/applied/applied-c-align-array-elements-32af40a768ee
//          // https://create.stephan-brumme.com/crc32/ //
//          https://rosettacode.org/wiki/Generate_lower_case_ASCII_alphabet //
//          https://www.codeproject.com/Articles/663443/Cplusplus-is-Fun-Optimal-Alphabetical-Order
//          //
//          https://cppsecrets.com/users/960210997110103971089710711510497116484964103109971051084699111109/Given-integer-n-find-the-nth-string-in-this-sequence-A-B-C-Z-AA-AB-AC-ZZ-AAA-AAB-AAZ-ABA-.php
//          https://www.careercup.com/question?id=14276663 //
//          https://stackoverflow.com/a/55074804/10152334 //
//          https://stackoverflow.com/questions/26429360/crc32-vs-crc32c //
//  OS: ALL                                                 //
//  CPU: ALL                                                //
//                                                          //
//////////////////////////////////////////////////////////////

#ifndef CRYPTO_CRC32_HPP_
#define CRYPTO_CRC32_HPP_

#if defined (__has_include) && (__has_include(<boost/crc.hpp>))
#include <boost/crc.hpp>
#else
#warning "No boost found, disable some function."
#endif

extern "C" {
#include "banned.h"
};

// intrinsics / prefetching
#    if (__AVX2__ || __AVX__ || __SSE3__ || __SSE__)
#include <xmmintrin.h>
#endif

#if (__cplusplus >= 201703L)
#include<string_view>
#else
#warning "No C++17, disable some function."
#endif

// defines __BYTE_ORDER as __LITTLE_ENDIAN or __BIG_ENDIAN
#include <sys/param.h>

/* CRC-32C (iSCSI) polynomial in reversed bit order. */
//#define POLY 0x82f63b78
/* CRC-32 (Ethernet, ZIP, etc.) polynomial in reversed bit order. */
#define POLY 0xEDB88320

#define CRC32_USE_LOOKUP_TABLE_BYTE
#define CRC32_USE_LOOKUP_TABLE_SLICING_BY_4
#define CRC32_USE_LOOKUP_TABLE_SLICING_BY_8
#define CRC32_USE_LOOKUP_TABLE_SLICING_BY_16

namespace my {
namespace crypto {

#if (BOOST_VERSION >= 106200)
#if (__cplusplus >= 201703L)
/**
 * This function process CRC32 hash from string
 * @ingroup Crypto_CRC32
 * @param my_string String text need to be calculate
 * @return uint32_t with CRC32 value
 *
 * @author Bensuperpc
 *
 * @see see also JAMCRC_Boost()
 */
uint32_t CRC32_Boost(std::string_view my_string);

/**
 * This function process JAMCRC hash from string
 * @ingroup Crypto_JAMCRC
 * @param my_string text to process
 * @return uint32_t with JAMCRC value
 *
 * @author Bensuperpc
 *
 * @see see also CRC32_Boost()
 */
uint32_t JAMCRC_Boost(std::string_view my_string);
#endif
#endif

/**
 * This function process CRC32 hash from void * const
 *
 * @ingroup Crypto_CRC32
 * @param buf void* text need to be calculate
 * @param len size_t text size
 * @param crc uint32_t least crc (0x0 if is empty)
 * @return uint32_t with CRC32 value
 *
 * @author Bensuperpc
 *
 * @see see also JAMCRC_Boost()
 */
uint32_t CRC32_Boost(const void *buf, size_t len, uint32_t crc);

/**
 * This function process CRC32 hash from void * const
 *
 * @ingroup Crypto_JAMCRC
 * @param buf void* text need to be calculate
 * @param len size_t text size
 * @param crc uint32_t least crc (0x0 if is empty)
 * @return uint32_t with CRC32 value
 *
 * @author Bensuperpc
 *
 * @see see also CRC32_Boost()
 */
uint32_t JAMCRC_Boost(const void *buf, size_t len, uint32_t crc);

/**
 * This function process CRC32 hash from void * const
 *
 * @ingroup Crypto_CRC32
 * @param buf void* text need to be calculate
 * @param len size_t text size
 * @param crc uint32_t least crc (0x0 if is empty)
 * @return uint32_t with CRC32 value
 *
 * @author ?
 *
 * @see see also JAMCRC_StackOverflow()
 */
uint32_t CRC32_StackOverflow(const void *buf, size_t len, uint32_t crc);

/**
 * This function process CRC32 hash from void * const
 *
 * @ingroup Crypto_JAMCRC
 * @param buf void* text need to be calculate
 * @param len size_t text size
 * @param crc uint32_t least crc (0x0 if is empty)
 * @return uint32_t with CRC32 value
 *
 * @author ?
 *
 * @see see also CRC32_StackOverflow()
 */
uint32_t JAMCRC_StackOverflow(const void *buf, size_t len, uint32_t crc);

/**
 * This function process CRC32 hash from void * const
 *
 * @ingroup Crypto_CRC32
 * @param data void* text need to be calculate
 * @param length size_t text size
 * @param previousCrc32 uint32_t least crc (0x0 if is empty)
 * @return uint32_t with CRC32 value
 *
 * @author stephan brumme
 *
 * @see see also JAMCRC_1byte_tableless()
 */
uint32_t CRC32_1byte_tableless(const void *data, size_t length,
                               uint32_t previousCrc32);

/**
 * This function process CRC32 hash from void * const
 *
 * @ingroup Crypto_JAMCRC
 * @param data void* text need to be calculate
 * @param length size_t text size
 * @param previousCrc32 uint32_t least crc (0x0 if is empty)
 * @return uint32_t with CRC32 value
 *
 * @author stephan brumme
 *
 * @see see also CRC32_1byte_tableless()
 */
uint32_t JAMCRC_1byte_tableless(const void *data, size_t length,
                                uint32_t previousCrc32);

/**
 * This function process CRC32 hash from void * const
 *
 * @ingroup Crypto_CRC32
 * @param data void* text need to be calculate
 * @param length size_t text size
 * @param previousCrc32 uint32_t least crc (0x0 if is empty)
 * @return uint32_t with CRC32 value
 *
 * @author stephan brumme
 *
 * @see see also JAMCRC_1byte_tableless2()
 */
uint32_t CRC32_1byte_tableless2(const void *data, size_t length,
                                uint32_t previousCrc32);

/**
 * This function process CRC32 hash from void * const
 *
 * @ingroup Crypto_JAMCRC
 * @param data void* text need to be calculate
 * @param length size_t text size
 * @param previousCrc32 uint32_t least crc (0x0 if is empty)
 * @return uint32_t with CRC32 value
 *
 * @author stephan brumme
 *
 * @see see also CRC32_1byte_tableless2()
 */
uint32_t JAMCRC_1byte_tableless2(const void *data, size_t length,
                                 uint32_t previousCrc32);

/**
 * This function process CRC32 hash from void * const
 *
 * @ingroup Crypto_CRC32
 * @param data void* text need to be calculate
 * @param length size_t text size
 * @param previousCrc32 uint32_t least crc (0x0 if is empty)
 * @return uint32_t with CRC32 value
 *
 * @author stephan brumme
 *
 * @see see also JAMCRC_bitwise()
 */
uint32_t CRC32_bitwise(const void *data, size_t length, uint32_t previousCrc32);

/**
 * This function process CRC32 hash from void * const
 *
 * @ingroup Crypto_JAMCRC
 * @param data void* text need to be calculate
 * @param length size_t text size
 * @param previousCrc32 uint32_t least crc (0x0 if is empty)
 * @return uint32_t with CRC32 value
 *
 * @author stephan brumme
 *
 * @see see also CRC32_bitwise()
 */
uint32_t JAMCRC_bitwise(const void *data, size_t length,
                        uint32_t previousCrc32);

/**
 * This function process CRC32 hash from void * const
 *
 * @ingroup Crypto_CRC32
 * @param data void* text need to be calculate
 * @param length size_t text size
 * @param previousCrc32 uint32_t least crc (0x0 if is empty)
 * @return uint32_t with CRC32 value
 *
 * @author stephan brumme
 *
 * @see see also JAMCRC_halfbyte()
 */
uint32_t CRC32_halfbyte(const void *data, size_t length,
                        uint32_t previousCrc32);

/**
 * This function process CRC32 hash from void * const
 *
 * @ingroup Crypto_JAMCRC
 * @param data void* text need to be calculate
 * @param length size_t text size
 * @param previousCrc32 uint32_t least crc (0x0 if is empty)
 * @return uint32_t with CRC32 value
 *
 * @author stephan brumme
 *
 * @see see also CRC32_halfbyte()
 */
uint32_t JAMCRC_halfbyte(const void *data, size_t length,
                         uint32_t previousCrc32);

/**
 * This function process CRC32 hash from void * const
 *
 * @ingroup Crypto_CRC32
 * @param data void* text need to be calculate
 * @param length size_t text size
 * @param previousCrc32 uint32_t least crc (0x0 if is empty)
 * @return uint32_t with CRC32 value
 *
 * @author stephan brumme
 *
 * @see see also JAMCRC_1byte()
 */
#ifdef CRC32_USE_LOOKUP_TABLE_BYTE
uint32_t CRC32_1byte(const void *data, size_t length, uint32_t previousCrc32);

/**
 * This function process CRC32 hash from void * const
 *
 * @ingroup Crypto_JAMCRC
 * @param data void* text need to be calculate
 * @param length size_t text size
 * @param previousCrc32 uint32_t least crc (0x0 if is empty)
 * @return uint32_t with CRC32 value
 *
 * @author stephan brumme
 *
 * @see see also CRC32_1byte()
 */
uint32_t JAMCRC_1byte(const void *data, size_t length, uint32_t previousCrc32);
#endif

#ifdef CRC32_USE_LOOKUP_TABLE_SLICING_BY_4

/**
 * This function process CRC32 hash from void * const
 *
 * @ingroup Crypto_CRC32
 * @param data void* text need to be calculate
 * @param length size_t text size
 * @param previousCrc32 uint32_t least crc (0x0 if is empty)
 * @return uint32_t with CRC32 value
 *
 * @author stephan brumme
 *
 * @see see also JAMCRC_4bytes()
 */
uint32_t CRC32_4bytes(const void *data, size_t length,
                      uint32_t previousCrc32 = 0);

/**
 * This function process CRC32 hash from void * const
 *
 * @ingroup Crypto_JAMCRC
 * @param data void* text need to be calculate
 * @param length size_t text size
 * @param previousCrc32 uint32_t least crc (0x0 if is empty)
 * @return uint32_t with CRC32 value
 *
 * @author stephan brumme
 *
 * @see see also CRC32_4bytes()
 */
uint32_t JAMCRC_4bytes(const void *data, size_t length,
                       uint32_t previousCrc32 = 0);
#endif

#ifdef CRC32_USE_LOOKUP_TABLE_SLICING_BY_8

/**
 * This function process CRC32 hash from void * const
 *
 * @ingroup Crypto_CRC32
 * @param data void* text need to be calculate
 * @param length size_t text size
 * @param previousCrc32 uint32_t least crc (0x0 if is empty)
 * @return uint32_t with CRC32 value
 *
 * @author stephan brumme
 *
 * @see see also CRC32_4x8bytes()
 */
uint32_t CRC32_8bytes(const void *data, size_t length,
                      uint32_t previousCrc32 = 0);

/**
 * This function process CRC32 hash from void * const
 *
 * @ingroup Crypto_CRC32
 * @param data void* text need to be calculate
 * @param length size_t text size
 * @param previousCrc32 uint32_t least crc (0x0 if is empty)
 * @return uint32_t with CRC32 value
 *
 * @author stephan brumme
 *
 * @see see also CRC32_8bytes()
 */
uint32_t CRC32_4x8bytes(const void *data, size_t length,
                        uint32_t previousCrc32 = 0);

/**
 * This function process CRC32 hash from void * const
 *
 * @ingroup Crypto_JAMCRC
 * @param data void* text need to be calculate
 * @param length size_t text size
 * @param previousCrc32 uint32_t least crc (0x0 if is empty)
 * @return uint32_t with JAMCRC value
 *
 * @author stephan brumme
 *
 * @see see also CRC32_4x8bytes()
 */
uint32_t JAMCRC_8bytes(const void *data, size_t length,
                       uint32_t previousCrc32 = 0);

/**
 * This function process CRC32 hash from void * const
 *
 * @ingroup Crypto_JAMCRC
 * @param data void* text need to be calculate
 * @param length size_t text size
 * @param previousCrc32 uint32_t least crc (0x0 if is empty)
 * @return uint32_t with JAMCRC value
 *
 * @author stephan brumme
 *
 * @see see also CRC32_4x8bytes()
 */
uint32_t JAMCRC_4x8bytes(const void *data, size_t length,
                         uint32_t previousCrc32 = 0);
#endif

#ifdef CRC32_USE_LOOKUP_TABLE_SLICING_BY_16
/**
 * This function process CRC32 hash from void * const
 *
 * @ingroup Crypto_CRC32
 * @param data void* text need to be calculate
 * @param length size_t text size
 * @param previousCrc32 uint32_t least crc (0x0 if is empty)
 * @return uint32_t with CRC32 value
 *
 * @author stephan brumme
 *
 * @see see also JAMCRC_16bytes()
 */
uint32_t CRC32_16bytes(const void *data, size_t length,
                       uint32_t previousCrc32 = 0);

/**
 * This function process CRC32 hash from void * const
 *
 * @ingroup Crypto_CRC32
 * @param data void* text need to be calculate
 * @param length size_t text size
 * @param previousCrc32 uint32_t least crc (0x0 if is empty)
 * @param prefetchAhead 256 by default
 * @return uint32_t with CRC32 value
 *
 * @author stephan brumme
 *
 * @see see also JAMCRC_16bytes_prefetch()
 */
uint32_t CRC32_16bytes_prefetch(const void *data, size_t length,
                                uint32_t previousCrc32 = 0,
                                size_t prefetchAhead = 256);

/**
 * This function process CRC32 hash from void * const
 *
 * @ingroup Crypto_JAMCRC
 * @param data void* text need to be calculate
 * @param length size_t text size
 * @param previousCrc32 uint32_t least crc (0x0 if is empty)
 * @return uint32_t with JAMCRC value
 *
 * @author stephan brumme
 *
 * @see see also CRC32_16bytes()
 */
uint32_t JAMCRC_16bytes(const void *data, size_t length,
                        uint32_t previousCrc32 = 0);

/**
 * This function process CRC32 hash from void * const
 *
 * @ingroup Crypto_JAMCRC
 * @param data void* text need to be calculate
 * @param length size_t text size
 * @param previousCrc32 uint32_t least crc (0x0 if is empty)
 * @param prefetchAhead 256 by default
 * @return uint32_t with JAMCRC value
 *
 * @author stephan brumme
 *
 * @see see also CRC32_16bytes_prefetch()
 */

uint32_t JAMCRC_16bytes_prefetch(const void *data, size_t length,
                                 uint32_t previousCrc32 = 0,
                                 size_t prefetchAhead = 256);
#endif

/**
 * This function process CRC32 hash from void * const
 *
 * @ingroup Crypto_CRC32
 * @param data void* text need to be calculate
 * @param length size_t text size
 * @param previousCrc32 uint32_t least crc (0x0 if is empty)
 * @return uint32_t with CRC32 value
 *
 * @author stephan brumme
 *
 * @see see also JAMCRC_fast()
 */
uint32_t CRC32_fast(const void *data, size_t length, uint32_t previousCrc32);

/**
 * This function process CRC32 hash from void * const
 *
 * @ingroup Crypto_JAMCRC
 * @param data void* text need to be calculate
 * @param length size_t text size
 * @param previousCrc32 uint32_t least crc (0x0 if is empty)
 * @return uint32_t with JAMCRC value
 *
 * @author stephan brumme
 *
 * @see see also CRC32_fast()
 */
uint32_t JAMCRC_fast(const void *data, size_t length, uint32_t previousCrc32);

} // namespace crypto
} // namespace my




#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 1234
#endif
#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN 4321
#endif

// define endianess and some integer data types
#if defined(_MSC_VER) || defined(__MINGW32__)
// Windows always little endian
#define __BYTE_ORDER __LITTLE_ENDIAN

#ifdef __MINGW32__
#define PREFETCH(location) __builtin_prefetch(location)
#else
#define PREFETCH(location) _mm_prefetch(location, _MM_HINT_T0)
#endif
#else

// intrinsics / prefetching
#ifdef __GNUC__
#define PREFETCH(location) __builtin_prefetch(location)
#else
// no prefetching
#define PREFETCH(location) ;
#endif
#endif

// abort if byte order is undefined
#if !defined(__BYTE_ORDER)
#error undefined byte order, compile with -D__BYTE_ORDER=1234 (if little endian) or -D__BYTE_ORDER=4321 (big endian)
#endif

namespace {
/// zlib's CRC32 polynomial
const uint32_t Polynomial = 0xEDB88320;

/// swap endianess
static inline uint32_t swap(uint32_t x) {
#if defined(__GNUC__) || defined(__clang__)
  return __builtin_bswap32(x);
#else
  return (x >> 24) | ((x >> 8) & 0x0000FF00) | ((x << 8) & 0x00FF0000) |
         (x << 24);
#endif
}

/// Slicing-By-16
#ifdef CRC32_USE_LOOKUP_TABLE_SLICING_BY_16
const size_t MaxSlice = 16;
#elif defined(CRC32_USE_LOOKUP_TABLE_SLICING_BY_8)
const size_t MaxSlice = 8;
#elif defined(CRC32_USE_LOOKUP_TABLE_SLICING_BY_4)
const size_t MaxSlice = 4;
#elif defined(CRC32_USE_LOOKUP_TABLE_BYTE)
const size_t MaxSlice = 1;
#else
#define NO_LUT // don't need Crc32Lookup at all
#endif

} // anonymous namespace

#ifndef NO_LUT
/// forward declaration, table is at the end of this file
extern const uint32_t
    Crc32Lookup[MaxSlice][256]; // extern is needed to keep compiler happy
#endif

#if (BOOST_VERSION >= 106200)
#if (__cplusplus >= 201703L)
uint32_t my::crypto::JAMCRC_Boost(std::string_view my_string) {
  boost::crc_32_type result;
  // ça c'est plus rapide que l'autre normalement pour le length. Ça donne le
  // nombre d'élément, donc si tu as plusieurs éléments qui sont à '\0'
  // forcément…
  result.process_bytes(my_string.data(), my_string.length());
  return ~result.checksum();
}

uint32_t my::crypto::CRC32_Boost(std::string_view my_string) {
  boost::crc_32_type result;
  // ça c'est plus rapide que l'autre normalement pour le length. Ça donne le
  // nombre d'élément, donc si tu as plusieurs éléments qui sont à '\0'
  // forcément…
  result.process_bytes(my_string.data(), my_string.length());
  return result.checksum();
}

uint32_t my::crypto::CRC32_Boost(const void *buf, size_t len, uint32_t crc) {
  boost::crc_32_type result;
  result.process_bytes(
      reinterpret_cast<unsigned char *>(const_cast<void *>(buf)), len);
  return ~result.checksum();
}

uint32_t my::crypto::JAMCRC_Boost(const void *buf, size_t len, uint32_t crc) {
  boost::crc_32_type result;
  result.process_bytes(
      reinterpret_cast<unsigned char *>(const_cast<void *>(buf)), len);
  return result.checksum();
}
#endif
#endif

uint32_t my::crypto::CRC32_StackOverflow(const void *buf, size_t len,
                                         uint32_t crc) {
  short k; // change int to short
  const uint8_t *data = reinterpret_cast<uint8_t *>(const_cast<void *>(buf));
  crc = ~crc;
  while (len--) {
    crc ^= *data++;
    for (k = 0; k < 8; k++)
      crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
    // crc = (crc >> 1) ^ (POLY & (0 - (crc & 1))); // Slower
  }
  return ~crc;
}

uint32_t my::crypto::JAMCRC_StackOverflow(const void *buf, size_t len,
                                          uint32_t crc) {
  short k; // change int to short
  const uint8_t *data = reinterpret_cast<uint8_t *>(const_cast<void *>(buf));
  crc = ~crc;
  while (len--) {
    crc ^= *data++;
    for (k = 0; k < 8; k++)
      crc = crc & 1 ? (crc >> 1) ^ POLY : crc >> 1;
    // crc = (crc >> 1) ^ (POLY & (0 - (crc & 1))); // Slower
  }
  return crc;
}

uint32_t my::crypto::CRC32_1byte_tableless(const void *data, size_t length,
                                           uint32_t previousCrc32) {
  uint32_t crc = ~previousCrc32; // same as previousCrc32 ^ 0xFFFFFFFF
  const uint8_t *current = (const uint8_t *)data;
  while (length-- != 0) {
    uint8_t s = uint8_t(crc) ^ *current++;
    uint32_t low = (s ^ (s << 6)) & 0xFF;
    uint32_t a = (low * ((1 << 23) + (1 << 14) + (1 << 2)));
    crc = (crc >> 8) ^ (low * ((1 << 24) + (1 << 16) + (1 << 8))) ^ a ^
          (a >> 1) ^ (low * ((1 << 20) + (1 << 12))) ^ (low << 19) ^
          (low << 17) ^ (low >> 2);
  }
  return ~crc; // same as crc ^ 0xFFFFFFFF
}

uint32_t my::crypto::JAMCRC_1byte_tableless(const void *data, size_t length,
                                            uint32_t previousCrc32) {
  uint32_t crc = ~previousCrc32; // same as previousCrc32 ^ 0xFFFFFFFF
  const uint8_t *current = (const uint8_t *)data;
  while (length-- != 0) {
    uint8_t s = uint8_t(crc) ^ *current++;
    // Hagai Gold made me aware of this table-less algorithm and send me code
    // polynomial 0xEDB88320 can be written in binary as
    // 11101101101110001000001100100000b reverse the bits (or just assume bit 0
    // is the first one) and we have bits set at position 0, 1, 2, 4, 5, 7, 8,
    // 10, 11, 12, 16, 22, 23, 26
    // => those are the shift offsets:
    // crc = (crc >> 8) ^
    //       t ^
    //      (t >>  1) ^ (t >>  2) ^ (t >>  4) ^ (t >>  5) ^  // == y
    //      (t >>  7) ^ (t >>  8) ^ (t >> 10) ^ (t >> 11) ^  // == y >> 6
    //      (t >> 12) ^ (t >> 16) ^                          // == z
    //      (t >> 22) ^ (t >> 26) ^                          // == z >> 10
    //      (t >> 23);
    // the fastest I can come up with:
    uint32_t low = (s ^ (s << 6)) & 0xFF;
    uint32_t a = (low * ((1 << 23) + (1 << 14) + (1 << 2)));
    crc = (crc >> 8) ^ (low * ((1 << 24) + (1 << 16) + (1 << 8))) ^ a ^
          (a >> 1) ^ (low * ((1 << 20) + (1 << 12))) ^ (low << 19) ^
          (low << 17) ^ (low >> 2);
    // Hagai's code:
    /*uint32_t t = (s ^ (s << 6)) << 24;
    // some temporaries to optimize XOR
    uint32_t x = (t >> 1) ^ (t >> 2);
    uint32_t y = x ^ (x >> 3);
    uint32_t z = (t >> 12) ^ (t >> 16);
    crc = (crc >> 8) ^
           t ^ (t >> 23) ^
           y ^ (y >>  6) ^
           z ^ (z >> 10);*/
  }
  return crc;
}

uint32_t my::crypto::CRC32_1byte_tableless2(const void *data, size_t length,
                                            uint32_t previousCrc32) {
  int32_t crc = static_cast<int32_t>(
      ~previousCrc32); // note: signed integer, right shift distributes sign bit
                       // into lower bits
  const uint8_t *current =
      reinterpret_cast<uint8_t *>(const_cast<void *>(data));

  while (length-- != 0) {
    crc = crc ^ *current++;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
    uint32_t c = (((crc << 31) >> 31) & ((POLY >> 7) ^ (POLY >> 1))) ^
                 (((crc << 30) >> 31) & ((POLY >> 6) ^ POLY)) ^
                 (((crc << 29) >> 31) & (POLY >> 5)) ^
                 (((crc << 28) >> 31) & (POLY >> 4)) ^
                 (((crc << 27) >> 31) & (POLY >> 3)) ^
                 (((crc << 26) >> 31) & (POLY >> 2)) ^
                 (((crc << 25) >> 31) & (POLY >> 1)) ^
                 (((crc << 24) >> 31) & POLY);
#pragma GCC diagnostic pop
    crc = (crc >> 8) ^ static_cast<int32_t>(
                           c); // convert to unsigned integer before right shift
  }

  return static_cast<uint32_t>(~crc); // same as crc ^ 0xFFFFFFFF
}

uint32_t my::crypto::JAMCRC_1byte_tableless2(const void *data, size_t length,
                                             uint32_t previousCrc32) {
  int32_t crc = static_cast<int32_t>(
      ~previousCrc32); // note: signed integer, right shift distributes sign bit
                       // into lower bits
  const uint8_t *current = reinterpret_cast<uint8_t *>(
      const_cast<void *>(data)); //(const uint8_t *)data;

  while (length-- != 0) {
    crc = crc ^ *current++;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
    uint32_t c = (((crc << 31) >> 31) & ((POLY >> 7) ^ (POLY >> 1))) ^
                 (((crc << 30) >> 31) & ((POLY >> 6) ^ POLY)) ^
                 (((crc << 29) >> 31) & (POLY >> 5)) ^
                 (((crc << 28) >> 31) & (POLY >> 4)) ^
                 (((crc << 27) >> 31) & (POLY >> 3)) ^
                 (((crc << 26) >> 31) & (POLY >> 2)) ^
                 (((crc << 25) >> 31) & (POLY >> 1)) ^
                 (((crc << 24) >> 31) & POLY);
#pragma GCC diagnostic pop
    crc = ((uint32_t)crc >> 8) ^
          static_cast<int32_t>(
              c); // convert to unsigned integer before right shift
  }

  return static_cast<uint32_t>(crc);
}

uint32_t my::crypto::CRC32_bitwise(const void *data, size_t length,
                                   uint32_t previousCrc32) {
  uint32_t crc = ~previousCrc32;
  unsigned char *current = reinterpret_cast<unsigned char *>(
      const_cast<void *>(data)); // reinterpret_cast<unsigned char *>(data);
  while (length--) {
    crc ^= *current++;
    for (unsigned int j = 0; j < 8; j++)
      crc = (crc >> 1) ^ (-int(crc & 1) & POLY);
  }
  return ~crc; // same as crc ^ 0xFFFFFFFF
}

uint32_t my::crypto::JAMCRC_bitwise(const void *data, size_t length,
                                    uint32_t previousCrc32) {
  uint32_t crc = ~previousCrc32;
  unsigned char *current =
      reinterpret_cast<unsigned char *>(const_cast<void *>(data));
  while (length--) {
    crc ^= *current++;
    for (unsigned int j = 0; j < 8; j++)
      crc = (crc >> 1) ^ (-int(crc & 1) & POLY);
  }
  return crc; // same as crc ^ 0xFFFFFFFF
}

uint32_t my::crypto::CRC32_halfbyte(const void *data, size_t length,
                                    uint32_t previousCrc32) {
  uint32_t crc = ~previousCrc32; // same as previousCrc32 ^ 0xFFFFFFFF
  const uint8_t *current = (const uint8_t *)data;

  /// look-up table for half-byte, same as crc32Lookup[0][16*i]
  static const uint32_t Crc32Lookup16[16] = {
      0x00000000, 0x1DB71064, 0x3B6E20C8, 0x26D930AC, 0x76DC4190, 0x6B6B51F4,
      0x4DB26158, 0x5005713C, 0xEDB88320, 0xF00F9344, 0xD6D6A3E8, 0xCB61B38C,
      0x9B64C2B0, 0x86D3D2D4, 0xA00AE278, 0xBDBDF21C};

  while (length-- != 0) {
    crc = Crc32Lookup16[(crc ^ *current) & 0x0F] ^ (crc >> 4);
    crc = Crc32Lookup16[(crc ^ (*current >> 4)) & 0x0F] ^ (crc >> 4);
    current++;
  }

  return ~crc; // same as crc ^ 0xFFFFFFFF
}

uint32_t my::crypto::JAMCRC_halfbyte(const void *data, size_t length,
                                     uint32_t previousCrc32) {
  uint32_t crc = ~previousCrc32; // same as previousCrc32 ^ 0xFFFFFFFF
  const uint8_t *current = (const uint8_t *)data;

  /// look-up table for half-byte, same as crc32Lookup[0][16*i]
  static const uint32_t Crc32Lookup16[16] = {
      0x00000000, 0x1DB71064, 0x3B6E20C8, 0x26D930AC, 0x76DC4190, 0x6B6B51F4,
      0x4DB26158, 0x5005713C, 0xEDB88320, 0xF00F9344, 0xD6D6A3E8, 0xCB61B38C,
      0x9B64C2B0, 0x86D3D2D4, 0xA00AE278, 0xBDBDF21C};

  while (length-- != 0) {
    crc = Crc32Lookup16[(crc ^ *current) & 0x0F] ^ (crc >> 4);
    crc = Crc32Lookup16[(crc ^ (*current >> 4)) & 0x0F] ^ (crc >> 4);
    current++;
  }

  return crc;
}

#ifdef CRC32_USE_LOOKUP_TABLE_BYTE
uint32_t my::crypto::CRC32_1byte(const void *data, size_t length,
                                 uint32_t previousCrc32) {
  uint32_t crc = ~previousCrc32; // same as previousCrc32 ^ 0xFFFFFFFF
  const uint8_t *current = (const uint8_t *)data;

  while (length-- != 0)
    crc = (crc >> 8) ^ Crc32Lookup[0][(crc & 0xFF) ^ *current++];

  return ~crc; // same as crc ^ 0xFFFFFFFF
}

uint32_t my::crypto::JAMCRC_1byte(const void *data, size_t length,
                                  uint32_t previousCrc32) {
  uint32_t crc = ~previousCrc32; // same as previousCrc32 ^ 0xFFFFFFFF
  const uint8_t *current = (const uint8_t *)data;

  while (length-- != 0)
    crc = (crc >> 8) ^ Crc32Lookup[0][(crc & 0xFF) ^ *current++];

  return crc;
}
#endif

#ifdef CRC32_USE_LOOKUP_TABLE_SLICING_BY_4
/// compute CRC32 (Slicing-by-4 algorithm)
uint32_t my::crypto::CRC32_4bytes(const void *data, size_t length,
                                  uint32_t previousCrc32) {
  uint32_t crc = ~previousCrc32; // same as previousCrc32 ^ 0xFFFFFFFF
  const uint32_t *current = (const uint32_t *)data;

  // process four bytes at once (Slicing-by-4)
  while (length >= 4) {
#if __BYTE_ORDER == __BIG_ENDIAN
    uint32_t one = *current++ ^ swap(crc);
    crc = Crc32Lookup[0][one & 0xFF] ^ Crc32Lookup[1][(one >> 8) & 0xFF] ^
          Crc32Lookup[2][(one >> 16) & 0xFF] ^
          Crc32Lookup[3][(one >> 24) & 0xFF];
#else
    uint32_t one = *current++ ^ crc;
    crc = Crc32Lookup[0][(one >> 24) & 0xFF] ^
          Crc32Lookup[1][(one >> 16) & 0xFF] ^
          Crc32Lookup[2][(one >> 8) & 0xFF] ^ Crc32Lookup[3][one & 0xFF];
#endif

    length -= 4;
  }

  const uint8_t *currentChar = (const uint8_t *)current;
  // remaining 1 to 3 bytes (standard algorithm)
  while (length-- != 0)
    crc = (crc >> 8) ^ Crc32Lookup[0][(crc & 0xFF) ^ *currentChar++];

  return ~crc; // same as crc ^ 0xFFFFFFFF
}

uint32_t my::crypto::JAMCRC_4bytes(const void *data, size_t length,
                                   uint32_t previousCrc32) {
  uint32_t crc = ~previousCrc32; // same as previousCrc32 ^ 0xFFFFFFFF
  const uint32_t *current = (const uint32_t *)data;

  // process four bytes at once (Slicing-by-4)
  while (length >= 4) {
#if __BYTE_ORDER == __BIG_ENDIAN
    uint32_t one = *current++ ^ swap(crc);
    crc = Crc32Lookup[0][one & 0xFF] ^ Crc32Lookup[1][(one >> 8) & 0xFF] ^
          Crc32Lookup[2][(one >> 16) & 0xFF] ^
          Crc32Lookup[3][(one >> 24) & 0xFF];
#else
    uint32_t one = *current++ ^ crc;
    crc = Crc32Lookup[0][(one >> 24) & 0xFF] ^
          Crc32Lookup[1][(one >> 16) & 0xFF] ^
          Crc32Lookup[2][(one >> 8) & 0xFF] ^ Crc32Lookup[3][one & 0xFF];
#endif

    length -= 4;
  }

  const uint8_t *currentChar = (const uint8_t *)current;
  // remaining 1 to 3 bytes (standard algorithm)
  while (length-- != 0)
    crc = (crc >> 8) ^ Crc32Lookup[0][(crc & 0xFF) ^ *currentChar++];

  return crc;
}
#endif

#ifdef CRC32_USE_LOOKUP_TABLE_SLICING_BY_8
/// compute CRC32 (Slicing-by-8 algorithm)
uint32_t my::crypto::CRC32_8bytes(const void *data, size_t length,
                                  uint32_t previousCrc32) {
  uint32_t crc = ~previousCrc32; // same as previousCrc32 ^ 0xFFFFFFFF
  const uint32_t *current = (const uint32_t *)data;

  // process eight bytes at once (Slicing-by-8)
  while (length >= 8) {
#if __BYTE_ORDER == __BIG_ENDIAN
    uint32_t one = *current++ ^ swap(crc);
    uint32_t two = *current++;
    crc = Crc32Lookup[0][two & 0xFF] ^ Crc32Lookup[1][(two >> 8) & 0xFF] ^
          Crc32Lookup[2][(two >> 16) & 0xFF] ^
          Crc32Lookup[3][(two >> 24) & 0xFF] ^ Crc32Lookup[4][one & 0xFF] ^
          Crc32Lookup[5][(one >> 8) & 0xFF] ^
          Crc32Lookup[6][(one >> 16) & 0xFF] ^
          Crc32Lookup[7][(one >> 24) & 0xFF];
#else
    uint32_t one = *current++ ^ crc;
    uint32_t two = *current++;
    crc = Crc32Lookup[0][(two >> 24) & 0xFF] ^
          Crc32Lookup[1][(two >> 16) & 0xFF] ^
          Crc32Lookup[2][(two >> 8) & 0xFF] ^ Crc32Lookup[3][two & 0xFF] ^
          Crc32Lookup[4][(one >> 24) & 0xFF] ^
          Crc32Lookup[5][(one >> 16) & 0xFF] ^
          Crc32Lookup[6][(one >> 8) & 0xFF] ^ Crc32Lookup[7][one & 0xFF];
#endif

    length -= 8;
  }

  const uint8_t *currentChar = (const uint8_t *)current;
  // remaining 1 to 7 bytes (standard algorithm)
  while (length-- != 0)
    crc = (crc >> 8) ^ Crc32Lookup[0][(crc & 0xFF) ^ *currentChar++];

  return ~crc; // same as crc ^ 0xFFFFFFFF
}

uint32_t my::crypto::JAMCRC_8bytes(const void *data, size_t length,
                                   uint32_t previousCrc32) {
  uint32_t crc = ~previousCrc32; // same as previousCrc32 ^ 0xFFFFFFFF
  const uint32_t *current = (const uint32_t *)data;

  // process eight bytes at once (Slicing-by-8)
  while (length >= 8) {
#if __BYTE_ORDER == __BIG_ENDIAN
    uint32_t one = *current++ ^ swap(crc);
    uint32_t two = *current++;
    crc = Crc32Lookup[0][two & 0xFF] ^ Crc32Lookup[1][(two >> 8) & 0xFF] ^
          Crc32Lookup[2][(two >> 16) & 0xFF] ^
          Crc32Lookup[3][(two >> 24) & 0xFF] ^ Crc32Lookup[4][one & 0xFF] ^
          Crc32Lookup[5][(one >> 8) & 0xFF] ^
          Crc32Lookup[6][(one >> 16) & 0xFF] ^
          Crc32Lookup[7][(one >> 24) & 0xFF];
#else
    uint32_t one = *current++ ^ crc;
    uint32_t two = *current++;
    crc = Crc32Lookup[0][(two >> 24) & 0xFF] ^
          Crc32Lookup[1][(two >> 16) & 0xFF] ^
          Crc32Lookup[2][(two >> 8) & 0xFF] ^ Crc32Lookup[3][two & 0xFF] ^
          Crc32Lookup[4][(one >> 24) & 0xFF] ^
          Crc32Lookup[5][(one >> 16) & 0xFF] ^
          Crc32Lookup[6][(one >> 8) & 0xFF] ^ Crc32Lookup[7][one & 0xFF];
#endif

    length -= 8;
  }

  const uint8_t *currentChar = (const uint8_t *)current;
  // remaining 1 to 7 bytes (standard algorithm)
  while (length-- != 0)
    crc = (crc >> 8) ^ Crc32Lookup[0][(crc & 0xFF) ^ *currentChar++];

  return crc;
}

/// compute CRC32 (Slicing-by-8 algorithm), unroll inner loop 4 times
uint32_t my::crypto::CRC32_4x8bytes(const void *data, size_t length,
                                    uint32_t previousCrc32) {
  uint32_t crc = ~previousCrc32; // same as previousCrc32 ^ 0xFFFFFFFF
  const uint32_t *current = (const uint32_t *)data;

  // enabling optimization (at least -O2) automatically unrolls the inner
  // for-loop
  const size_t Unroll = 4;
  const size_t BytesAtOnce = 8 * Unroll;

  // process 4x eight bytes at once (Slicing-by-8)
  while (length >= BytesAtOnce) {
    for (size_t unrolling = 0; unrolling < Unroll; unrolling++) {
#if __BYTE_ORDER == __BIG_ENDIAN
      uint32_t one = *current++ ^ swap(crc);
      uint32_t two = *current++;
      crc = Crc32Lookup[0][two & 0xFF] ^ Crc32Lookup[1][(two >> 8) & 0xFF] ^
            Crc32Lookup[2][(two >> 16) & 0xFF] ^
            Crc32Lookup[3][(two >> 24) & 0xFF] ^ Crc32Lookup[4][one & 0xFF] ^
            Crc32Lookup[5][(one >> 8) & 0xFF] ^
            Crc32Lookup[6][(one >> 16) & 0xFF] ^
            Crc32Lookup[7][(one >> 24) & 0xFF];
#else
      uint32_t one = *current++ ^ crc;
      uint32_t two = *current++;
      crc = Crc32Lookup[0][(two >> 24) & 0xFF] ^
            Crc32Lookup[1][(two >> 16) & 0xFF] ^
            Crc32Lookup[2][(two >> 8) & 0xFF] ^ Crc32Lookup[3][two & 0xFF] ^
            Crc32Lookup[4][(one >> 24) & 0xFF] ^
            Crc32Lookup[5][(one >> 16) & 0xFF] ^
            Crc32Lookup[6][(one >> 8) & 0xFF] ^ Crc32Lookup[7][one & 0xFF];
#endif
    }

    length -= BytesAtOnce;
  }

  const uint8_t *currentChar = (const uint8_t *)current;
  // remaining 1 to 31 bytes (standard algorithm)
  while (length-- != 0)
    crc = (crc >> 8) ^ Crc32Lookup[0][(crc & 0xFF) ^ *currentChar++];

  return ~crc; // same as crc ^ 0xFFFFFFFF
}

uint32_t my::crypto::JAMCRC_4x8bytes(const void *data, size_t length,
                                     uint32_t previousCrc32) {
  uint32_t crc = ~previousCrc32; // same as previousCrc32 ^ 0xFFFFFFFF
  const uint32_t *current = (const uint32_t *)data;

  // enabling optimization (at least -O2) automatically unrolls the inner
  // for-loop
  const size_t Unroll = 4;
  const size_t BytesAtOnce = 8 * Unroll;

  // process 4x eight bytes at once (Slicing-by-8)
  while (length >= BytesAtOnce) {
    for (size_t unrolling = 0; unrolling < Unroll; unrolling++) {
#if __BYTE_ORDER == __BIG_ENDIAN
      uint32_t one = *current++ ^ swap(crc);
      uint32_t two = *current++;
      crc = Crc32Lookup[0][two & 0xFF] ^ Crc32Lookup[1][(two >> 8) & 0xFF] ^
            Crc32Lookup[2][(two >> 16) & 0xFF] ^
            Crc32Lookup[3][(two >> 24) & 0xFF] ^ Crc32Lookup[4][one & 0xFF] ^
            Crc32Lookup[5][(one >> 8) & 0xFF] ^
            Crc32Lookup[6][(one >> 16) & 0xFF] ^
            Crc32Lookup[7][(one >> 24) & 0xFF];
#else
      uint32_t one = *current++ ^ crc;
      uint32_t two = *current++;
      crc = Crc32Lookup[0][(two >> 24) & 0xFF] ^
            Crc32Lookup[1][(two >> 16) & 0xFF] ^
            Crc32Lookup[2][(two >> 8) & 0xFF] ^ Crc32Lookup[3][two & 0xFF] ^
            Crc32Lookup[4][(one >> 24) & 0xFF] ^
            Crc32Lookup[5][(one >> 16) & 0xFF] ^
            Crc32Lookup[6][(one >> 8) & 0xFF] ^ Crc32Lookup[7][one & 0xFF];
#endif
    }

    length -= BytesAtOnce;
  }

  const uint8_t *currentChar = (const uint8_t *)current;
  // remaining 1 to 31 bytes (standard algorithm)
  while (length-- != 0)
    crc = (crc >> 8) ^ Crc32Lookup[0][(crc & 0xFF) ^ *currentChar++];

  return crc;
}
#endif // CRC32_USE_LOOKUP_TABLE_SLICING_BY_8

#ifdef CRC32_USE_LOOKUP_TABLE_SLICING_BY_16
/// compute CRC32 (Slicing-by-16 algorithm)
uint32_t my::crypto::CRC32_16bytes(const void *data, size_t length,
                                   uint32_t previousCrc32) {
  uint32_t crc = ~previousCrc32; // same as previousCrc32 ^ 0xFFFFFFFF
  const uint32_t *current = (const uint32_t *)data;

  // enabling optimization (at least -O2) automatically unrolls the inner
  // for-loop
  const size_t Unroll = 4;
  const size_t BytesAtOnce = 16 * Unroll;

  while (length >= BytesAtOnce) {
    for (size_t unrolling = 0; unrolling < Unroll; unrolling++) {
#if __BYTE_ORDER == __BIG_ENDIAN
      uint32_t one = *current++ ^ swap(crc);
      uint32_t two = *current++;
      uint32_t three = *current++;
      uint32_t four = *current++;
      crc = Crc32Lookup[0][four & 0xFF] ^ Crc32Lookup[1][(four >> 8) & 0xFF] ^
            Crc32Lookup[2][(four >> 16) & 0xFF] ^
            Crc32Lookup[3][(four >> 24) & 0xFF] ^ Crc32Lookup[4][three & 0xFF] ^
            Crc32Lookup[5][(three >> 8) & 0xFF] ^
            Crc32Lookup[6][(three >> 16) & 0xFF] ^
            Crc32Lookup[7][(three >> 24) & 0xFF] ^ Crc32Lookup[8][two & 0xFF] ^
            Crc32Lookup[9][(two >> 8) & 0xFF] ^
            Crc32Lookup[10][(two >> 16) & 0xFF] ^
            Crc32Lookup[11][(two >> 24) & 0xFF] ^ Crc32Lookup[12][one & 0xFF] ^
            Crc32Lookup[13][(one >> 8) & 0xFF] ^
            Crc32Lookup[14][(one >> 16) & 0xFF] ^
            Crc32Lookup[15][(one >> 24) & 0xFF];
#else
      uint32_t one = *current++ ^ crc;
      uint32_t two = *current++;
      uint32_t three = *current++;
      uint32_t four = *current++;
      crc = Crc32Lookup[0][(four >> 24) & 0xFF] ^
            Crc32Lookup[1][(four >> 16) & 0xFF] ^
            Crc32Lookup[2][(four >> 8) & 0xFF] ^ Crc32Lookup[3][four & 0xFF] ^
            Crc32Lookup[4][(three >> 24) & 0xFF] ^
            Crc32Lookup[5][(three >> 16) & 0xFF] ^
            Crc32Lookup[6][(three >> 8) & 0xFF] ^ Crc32Lookup[7][three & 0xFF] ^
            Crc32Lookup[8][(two >> 24) & 0xFF] ^
            Crc32Lookup[9][(two >> 16) & 0xFF] ^
            Crc32Lookup[10][(two >> 8) & 0xFF] ^ Crc32Lookup[11][two & 0xFF] ^
            Crc32Lookup[12][(one >> 24) & 0xFF] ^
            Crc32Lookup[13][(one >> 16) & 0xFF] ^
            Crc32Lookup[14][(one >> 8) & 0xFF] ^ Crc32Lookup[15][one & 0xFF];
#endif
    }

    length -= BytesAtOnce;
  }

  const uint8_t *currentChar = (const uint8_t *)current;
  // remaining 1 to 63 bytes (standard algorithm)
  while (length-- != 0)
    crc = (crc >> 8) ^ Crc32Lookup[0][(crc & 0xFF) ^ *currentChar++];

  return ~crc; // same as crc ^ 0xFFFFFFFF
}

uint32_t my::crypto::JAMCRC_16bytes(const void *data, size_t length,
                                    uint32_t previousCrc32) {
  uint32_t crc = ~previousCrc32; // same as previousCrc32 ^ 0xFFFFFFFF
  const uint32_t *current = (const uint32_t *)data;

  // enabling optimization (at least -O2) automatically unrolls the inner
  // for-loop
  const size_t Unroll = 4;
  const size_t BytesAtOnce = 16 * Unroll;

  while (length >= BytesAtOnce) {
    for (size_t unrolling = 0; unrolling < Unroll; unrolling++) {
#if __BYTE_ORDER == __BIG_ENDIAN
      uint32_t one = *current++ ^ swap(crc);
      uint32_t two = *current++;
      uint32_t three = *current++;
      uint32_t four = *current++;
      crc = Crc32Lookup[0][four & 0xFF] ^ Crc32Lookup[1][(four >> 8) & 0xFF] ^
            Crc32Lookup[2][(four >> 16) & 0xFF] ^
            Crc32Lookup[3][(four >> 24) & 0xFF] ^ Crc32Lookup[4][three & 0xFF] ^
            Crc32Lookup[5][(three >> 8) & 0xFF] ^
            Crc32Lookup[6][(three >> 16) & 0xFF] ^
            Crc32Lookup[7][(three >> 24) & 0xFF] ^ Crc32Lookup[8][two & 0xFF] ^
            Crc32Lookup[9][(two >> 8) & 0xFF] ^
            Crc32Lookup[10][(two >> 16) & 0xFF] ^
            Crc32Lookup[11][(two >> 24) & 0xFF] ^ Crc32Lookup[12][one & 0xFF] ^
            Crc32Lookup[13][(one >> 8) & 0xFF] ^
            Crc32Lookup[14][(one >> 16) & 0xFF] ^
            Crc32Lookup[15][(one >> 24) & 0xFF];
#else
      uint32_t one = *current++ ^ crc;
      uint32_t two = *current++;
      uint32_t three = *current++;
      uint32_t four = *current++;
      crc = Crc32Lookup[0][(four >> 24) & 0xFF] ^
            Crc32Lookup[1][(four >> 16) & 0xFF] ^
            Crc32Lookup[2][(four >> 8) & 0xFF] ^ Crc32Lookup[3][four & 0xFF] ^
            Crc32Lookup[4][(three >> 24) & 0xFF] ^
            Crc32Lookup[5][(three >> 16) & 0xFF] ^
            Crc32Lookup[6][(three >> 8) & 0xFF] ^ Crc32Lookup[7][three & 0xFF] ^
            Crc32Lookup[8][(two >> 24) & 0xFF] ^
            Crc32Lookup[9][(two >> 16) & 0xFF] ^
            Crc32Lookup[10][(two >> 8) & 0xFF] ^ Crc32Lookup[11][two & 0xFF] ^
            Crc32Lookup[12][(one >> 24) & 0xFF] ^
            Crc32Lookup[13][(one >> 16) & 0xFF] ^
            Crc32Lookup[14][(one >> 8) & 0xFF] ^ Crc32Lookup[15][one & 0xFF];
#endif
    }

    length -= BytesAtOnce;
  }

  const uint8_t *currentChar = (const uint8_t *)current;
  // remaining 1 to 63 bytes (standard algorithm)
  while (length-- != 0)
    crc = (crc >> 8) ^ Crc32Lookup[0][(crc & 0xFF) ^ *currentChar++];

  return crc;
}

/// compute CRC32 (Slicing-by-16 algorithm, prefetch upcoming data blocks)
uint32_t my::crypto::CRC32_16bytes_prefetch(const void *data, size_t length,
                                            uint32_t previousCrc32,
                                            size_t prefetchAhead) {
  // CRC code is identical to CRC32_16bytes (including unrolling), only added
  // prefetching 256 bytes look-ahead seems to be the sweet spot on Core i7 CPUs

  uint32_t crc = ~previousCrc32; // same as previousCrc32 ^ 0xFFFFFFFF
  const uint32_t *current = (const uint32_t *)data;

  // enabling optimization (at least -O2) automatically unrolls the for-loop
  const size_t Unroll = 4;
  const size_t BytesAtOnce = 16 * Unroll;

  while (length >= BytesAtOnce + prefetchAhead) {
    PREFETCH(((const char *)current) + prefetchAhead);

    for (size_t unrolling = 0; unrolling < Unroll; unrolling++) {
#if __BYTE_ORDER == __BIG_ENDIAN
      uint32_t one = *current++ ^ swap(crc);
      uint32_t two = *current++;
      uint32_t three = *current++;
      uint32_t four = *current++;
      crc = Crc32Lookup[0][four & 0xFF] ^ Crc32Lookup[1][(four >> 8) & 0xFF] ^
            Crc32Lookup[2][(four >> 16) & 0xFF] ^
            Crc32Lookup[3][(four >> 24) & 0xFF] ^ Crc32Lookup[4][three & 0xFF] ^
            Crc32Lookup[5][(three >> 8) & 0xFF] ^
            Crc32Lookup[6][(three >> 16) & 0xFF] ^
            Crc32Lookup[7][(three >> 24) & 0xFF] ^ Crc32Lookup[8][two & 0xFF] ^
            Crc32Lookup[9][(two >> 8) & 0xFF] ^
            Crc32Lookup[10][(two >> 16) & 0xFF] ^
            Crc32Lookup[11][(two >> 24) & 0xFF] ^ Crc32Lookup[12][one & 0xFF] ^
            Crc32Lookup[13][(one >> 8) & 0xFF] ^
            Crc32Lookup[14][(one >> 16) & 0xFF] ^
            Crc32Lookup[15][(one >> 24) & 0xFF];
#else
      uint32_t one = *current++ ^ crc;
      uint32_t two = *current++;
      uint32_t three = *current++;
      uint32_t four = *current++;
      crc = Crc32Lookup[0][(four >> 24) & 0xFF] ^
            Crc32Lookup[1][(four >> 16) & 0xFF] ^
            Crc32Lookup[2][(four >> 8) & 0xFF] ^ Crc32Lookup[3][four & 0xFF] ^
            Crc32Lookup[4][(three >> 24) & 0xFF] ^
            Crc32Lookup[5][(three >> 16) & 0xFF] ^
            Crc32Lookup[6][(three >> 8) & 0xFF] ^ Crc32Lookup[7][three & 0xFF] ^
            Crc32Lookup[8][(two >> 24) & 0xFF] ^
            Crc32Lookup[9][(two >> 16) & 0xFF] ^
            Crc32Lookup[10][(two >> 8) & 0xFF] ^ Crc32Lookup[11][two & 0xFF] ^
            Crc32Lookup[12][(one >> 24) & 0xFF] ^
            Crc32Lookup[13][(one >> 16) & 0xFF] ^
            Crc32Lookup[14][(one >> 8) & 0xFF] ^ Crc32Lookup[15][one & 0xFF];
#endif
    }

    length -= BytesAtOnce;
  }

  const uint8_t *currentChar = (const uint8_t *)current;
  // remaining 1 to 63 bytes (standard algorithm)
  while (length-- != 0)
    crc = (crc >> 8) ^ Crc32Lookup[0][(crc & 0xFF) ^ *currentChar++];

  return ~crc; // same as crc ^ 0xFFFFFFFF
}

uint32_t my::crypto::JAMCRC_16bytes_prefetch(const void *data, size_t length,
                                             uint32_t previousCrc32,
                                             size_t prefetchAhead) {
  // CRC code is identical to CRC32_16bytes (including unrolling), only added
  // prefetching 256 bytes look-ahead seems to be the sweet spot on Core i7 CPUs

  uint32_t crc = ~previousCrc32; // same as previousCrc32 ^ 0xFFFFFFFF
  const uint32_t *current = (const uint32_t *)data;

  // enabling optimization (at least -O2) automatically unrolls the for-loop
  const size_t Unroll = 4;
  const size_t BytesAtOnce = 16 * Unroll;

  while (length >= BytesAtOnce + prefetchAhead) {
    PREFETCH(((const char *)current) + prefetchAhead);

    for (size_t unrolling = 0; unrolling < Unroll; unrolling++) {
#if __BYTE_ORDER == __BIG_ENDIAN
      uint32_t one = *current++ ^ swap(crc);
      uint32_t two = *current++;
      uint32_t three = *current++;
      uint32_t four = *current++;
      crc = Crc32Lookup[0][four & 0xFF] ^ Crc32Lookup[1][(four >> 8) & 0xFF] ^
            Crc32Lookup[2][(four >> 16) & 0xFF] ^
            Crc32Lookup[3][(four >> 24) & 0xFF] ^ Crc32Lookup[4][three & 0xFF] ^
            Crc32Lookup[5][(three >> 8) & 0xFF] ^
            Crc32Lookup[6][(three >> 16) & 0xFF] ^
            Crc32Lookup[7][(three >> 24) & 0xFF] ^ Crc32Lookup[8][two & 0xFF] ^
            Crc32Lookup[9][(two >> 8) & 0xFF] ^
            Crc32Lookup[10][(two >> 16) & 0xFF] ^
            Crc32Lookup[11][(two >> 24) & 0xFF] ^ Crc32Lookup[12][one & 0xFF] ^
            Crc32Lookup[13][(one >> 8) & 0xFF] ^
            Crc32Lookup[14][(one >> 16) & 0xFF] ^
            Crc32Lookup[15][(one >> 24) & 0xFF];
#else
      uint32_t one = *current++ ^ crc;
      uint32_t two = *current++;
      uint32_t three = *current++;
      uint32_t four = *current++;
      crc = Crc32Lookup[0][(four >> 24) & 0xFF] ^
            Crc32Lookup[1][(four >> 16) & 0xFF] ^
            Crc32Lookup[2][(four >> 8) & 0xFF] ^ Crc32Lookup[3][four & 0xFF] ^
            Crc32Lookup[4][(three >> 24) & 0xFF] ^
            Crc32Lookup[5][(three >> 16) & 0xFF] ^
            Crc32Lookup[6][(three >> 8) & 0xFF] ^ Crc32Lookup[7][three & 0xFF] ^
            Crc32Lookup[8][(two >> 24) & 0xFF] ^
            Crc32Lookup[9][(two >> 16) & 0xFF] ^
            Crc32Lookup[10][(two >> 8) & 0xFF] ^ Crc32Lookup[11][two & 0xFF] ^
            Crc32Lookup[12][(one >> 24) & 0xFF] ^
            Crc32Lookup[13][(one >> 16) & 0xFF] ^
            Crc32Lookup[14][(one >> 8) & 0xFF] ^ Crc32Lookup[15][one & 0xFF];
#endif
    }

    length -= BytesAtOnce;
  }

  const uint8_t *currentChar = (const uint8_t *)current;
  // remaining 1 to 63 bytes (standard algorithm)
  while (length-- != 0)
    crc = (crc >> 8) ^ Crc32Lookup[0][(crc & 0xFF) ^ *currentChar++];

  return crc;
}
#endif

/// compute CRC32 using the fastest algorithm for large datasets on modern CPUs
uint32_t my::crypto::CRC32_fast(const void *data, size_t length,
                                uint32_t previousCrc32) {
#ifdef CRC32_USE_LOOKUP_TABLE_SLICING_BY_16
  return CRC32_16bytes(data, length, previousCrc32);
#elif defined(CRC32_USE_LOOKUP_TABLE_SLICING_BY_8)
  return CRC32_8bytes(data, length, previousCrc32);
#elif defined(CRC32_USE_LOOKUP_TABLE_SLICING_BY_4)
  return CRC32_4bytes(data, length, previousCrc32);
#elif defined(CRC32_USE_LOOKUP_TABLE_BYTE)
  return CRC32_1byte(data, length, previousCrc32);
#else
  return CRC32_halfbyte(data, length, previousCrc32);
#endif
}

uint32_t my::crypto::JAMCRC_fast(const void *data, size_t length,
                                 uint32_t previousCrc32) {
#ifdef CRC32_USE_LOOKUP_TABLE_SLICING_BY_16
  return JAMCRC_16bytes(data, length, previousCrc32);
#elif defined(CRC32_USE_LOOKUP_TABLE_SLICING_BY_8)
  return JAMCRC_8bytes(data, length, previousCrc32);
#elif defined(CRC32_USE_LOOKUP_TABLE_SLICING_BY_4)
  return JAMCRC_4bytes(data, length, previousCrc32);
#elif defined(CRC32_USE_LOOKUP_TABLE_BYTE)
  return JAMCRC_1byte(data, length, previousCrc32);
#else
  return JAMCRC_halfbyte(data, length, previousCrc32);
#endif
}

// //////////////////////////////////////////////////////////
// constants

#ifndef NO_LUT
/// look-up table, already declared above
const uint32_t Crc32Lookup[MaxSlice][256] = {
    //// same algorithm as crc32_bitwise
    // for (int i = 0; i <= 0xFF; i++)
    //{
    //  uint32_t crc = i;
    //  for (int j = 0; j < 8; j++)
    //    crc = (crc >> 1) ^ ((crc & 1) * Polynomial);
    //  Crc32Lookup[0][i] = crc;
    //}
    //// ... and the following slicing-by-8 algorithm (from Intel):
    ////
    ///http://www.intel.com/technology/comms/perfnet/download/CRC_generators.pdf
    //// http://sourceforge.net/projects/slicing-by-8/
    // for (int slice = 1; slice < MaxSlice; slice++)
    //  Crc32Lookup[slice][i] = (Crc32Lookup[slice - 1][i] >> 8) ^
    //  Crc32Lookup[0][Crc32Lookup[slice - 1][i] & 0xFF];
    {
        // note: the first number of every second row corresponds to the
        // half-byte look-up table !
        0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F,
        0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
        0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2,
        0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
        0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
        0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
        0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
        0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
        0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423,
        0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
        0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x01DB7106,
        0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
        0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D,
        0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
        0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950,
        0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
        0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7,
        0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
        0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA,
        0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
        0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
        0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
        0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84,
        0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
        0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
        0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
        0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E,
        0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
        0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55,
        0x316E8EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
        0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28,
        0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
        0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F,
        0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
        0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
        0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
        0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69,
        0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
        0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC,
        0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
        0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693,
        0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
        0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D,
    }

#if defined(CRC32_USE_LOOKUP_TABLE_SLICING_BY_4) ||                            \
    defined(CRC32_USE_LOOKUP_TABLE_SLICING_BY_8) ||                            \
    defined(CRC32_USE_LOOKUP_TABLE_SLICING_BY_16)
    // beyond this point only relevant for Slicing-by-4, Slicing-by-8 and
    // Slicing-by-16
    ,
    {
        0x00000000, 0x191B3141, 0x32366282, 0x2B2D53C3, 0x646CC504, 0x7D77F445,
        0x565AA786, 0x4F4196C7, 0xC8D98A08, 0xD1C2BB49, 0xFAEFE88A, 0xE3F4D9CB,
        0xACB54F0C, 0xB5AE7E4D, 0x9E832D8E, 0x87981CCF, 0x4AC21251, 0x53D92310,
        0x78F470D3, 0x61EF4192, 0x2EAED755, 0x37B5E614, 0x1C98B5D7, 0x05838496,
        0x821B9859, 0x9B00A918, 0xB02DFADB, 0xA936CB9A, 0xE6775D5D, 0xFF6C6C1C,
        0xD4413FDF, 0xCD5A0E9E, 0x958424A2, 0x8C9F15E3, 0xA7B24620, 0xBEA97761,
        0xF1E8E1A6, 0xE8F3D0E7, 0xC3DE8324, 0xDAC5B265, 0x5D5DAEAA, 0x44469FEB,
        0x6F6BCC28, 0x7670FD69, 0x39316BAE, 0x202A5AEF, 0x0B07092C, 0x121C386D,
        0xDF4636F3, 0xC65D07B2, 0xED705471, 0xF46B6530, 0xBB2AF3F7, 0xA231C2B6,
        0x891C9175, 0x9007A034, 0x179FBCFB, 0x0E848DBA, 0x25A9DE79, 0x3CB2EF38,
        0x73F379FF, 0x6AE848BE, 0x41C51B7D, 0x58DE2A3C, 0xF0794F05, 0xE9627E44,
        0xC24F2D87, 0xDB541CC6, 0x94158A01, 0x8D0EBB40, 0xA623E883, 0xBF38D9C2,
        0x38A0C50D, 0x21BBF44C, 0x0A96A78F, 0x138D96CE, 0x5CCC0009, 0x45D73148,
        0x6EFA628B, 0x77E153CA, 0xBABB5D54, 0xA3A06C15, 0x888D3FD6, 0x91960E97,
        0xDED79850, 0xC7CCA911, 0xECE1FAD2, 0xF5FACB93, 0x7262D75C, 0x6B79E61D,
        0x4054B5DE, 0x594F849F, 0x160E1258, 0x0F152319, 0x243870DA, 0x3D23419B,
        0x65FD6BA7, 0x7CE65AE6, 0x57CB0925, 0x4ED03864, 0x0191AEA3, 0x188A9FE2,
        0x33A7CC21, 0x2ABCFD60, 0xAD24E1AF, 0xB43FD0EE, 0x9F12832D, 0x8609B26C,
        0xC94824AB, 0xD05315EA, 0xFB7E4629, 0xE2657768, 0x2F3F79F6, 0x362448B7,
        0x1D091B74, 0x04122A35, 0x4B53BCF2, 0x52488DB3, 0x7965DE70, 0x607EEF31,
        0xE7E6F3FE, 0xFEFDC2BF, 0xD5D0917C, 0xCCCBA03D, 0x838A36FA, 0x9A9107BB,
        0xB1BC5478, 0xA8A76539, 0x3B83984B, 0x2298A90A, 0x09B5FAC9, 0x10AECB88,
        0x5FEF5D4F, 0x46F46C0E, 0x6DD93FCD, 0x74C20E8C, 0xF35A1243, 0xEA412302,
        0xC16C70C1, 0xD8774180, 0x9736D747, 0x8E2DE606, 0xA500B5C5, 0xBC1B8484,
        0x71418A1A, 0x685ABB5B, 0x4377E898, 0x5A6CD9D9, 0x152D4F1E, 0x0C367E5F,
        0x271B2D9C, 0x3E001CDD, 0xB9980012, 0xA0833153, 0x8BAE6290, 0x92B553D1,
        0xDDF4C516, 0xC4EFF457, 0xEFC2A794, 0xF6D996D5, 0xAE07BCE9, 0xB71C8DA8,
        0x9C31DE6B, 0x852AEF2A, 0xCA6B79ED, 0xD37048AC, 0xF85D1B6F, 0xE1462A2E,
        0x66DE36E1, 0x7FC507A0, 0x54E85463, 0x4DF36522, 0x02B2F3E5, 0x1BA9C2A4,
        0x30849167, 0x299FA026, 0xE4C5AEB8, 0xFDDE9FF9, 0xD6F3CC3A, 0xCFE8FD7B,
        0x80A96BBC, 0x99B25AFD, 0xB29F093E, 0xAB84387F, 0x2C1C24B0, 0x350715F1,
        0x1E2A4632, 0x07317773, 0x4870E1B4, 0x516BD0F5, 0x7A468336, 0x635DB277,
        0xCBFAD74E, 0xD2E1E60F, 0xF9CCB5CC, 0xE0D7848D, 0xAF96124A, 0xB68D230B,
        0x9DA070C8, 0x84BB4189, 0x03235D46, 0x1A386C07, 0x31153FC4, 0x280E0E85,
        0x674F9842, 0x7E54A903, 0x5579FAC0, 0x4C62CB81, 0x8138C51F, 0x9823F45E,
        0xB30EA79D, 0xAA1596DC, 0xE554001B, 0xFC4F315A, 0xD7626299, 0xCE7953D8,
        0x49E14F17, 0x50FA7E56, 0x7BD72D95, 0x62CC1CD4, 0x2D8D8A13, 0x3496BB52,
        0x1FBBE891, 0x06A0D9D0, 0x5E7EF3EC, 0x4765C2AD, 0x6C48916E, 0x7553A02F,
        0x3A1236E8, 0x230907A9, 0x0824546A, 0x113F652B, 0x96A779E4, 0x8FBC48A5,
        0xA4911B66, 0xBD8A2A27, 0xF2CBBCE0, 0xEBD08DA1, 0xC0FDDE62, 0xD9E6EF23,
        0x14BCE1BD, 0x0DA7D0FC, 0x268A833F, 0x3F91B27E, 0x70D024B9, 0x69CB15F8,
        0x42E6463B, 0x5BFD777A, 0xDC656BB5, 0xC57E5AF4, 0xEE530937, 0xF7483876,
        0xB809AEB1, 0xA1129FF0, 0x8A3FCC33, 0x9324FD72,
    },

    {
        0x00000000, 0x01C26A37, 0x0384D46E, 0x0246BE59, 0x0709A8DC, 0x06CBC2EB,
        0x048D7CB2, 0x054F1685, 0x0E1351B8, 0x0FD13B8F, 0x0D9785D6, 0x0C55EFE1,
        0x091AF964, 0x08D89353, 0x0A9E2D0A, 0x0B5C473D, 0x1C26A370, 0x1DE4C947,
        0x1FA2771E, 0x1E601D29, 0x1B2F0BAC, 0x1AED619B, 0x18ABDFC2, 0x1969B5F5,
        0x1235F2C8, 0x13F798FF, 0x11B126A6, 0x10734C91, 0x153C5A14, 0x14FE3023,
        0x16B88E7A, 0x177AE44D, 0x384D46E0, 0x398F2CD7, 0x3BC9928E, 0x3A0BF8B9,
        0x3F44EE3C, 0x3E86840B, 0x3CC03A52, 0x3D025065, 0x365E1758, 0x379C7D6F,
        0x35DAC336, 0x3418A901, 0x3157BF84, 0x3095D5B3, 0x32D36BEA, 0x331101DD,
        0x246BE590, 0x25A98FA7, 0x27EF31FE, 0x262D5BC9, 0x23624D4C, 0x22A0277B,
        0x20E69922, 0x2124F315, 0x2A78B428, 0x2BBADE1F, 0x29FC6046, 0x283E0A71,
        0x2D711CF4, 0x2CB376C3, 0x2EF5C89A, 0x2F37A2AD, 0x709A8DC0, 0x7158E7F7,
        0x731E59AE, 0x72DC3399, 0x7793251C, 0x76514F2B, 0x7417F172, 0x75D59B45,
        0x7E89DC78, 0x7F4BB64F, 0x7D0D0816, 0x7CCF6221, 0x798074A4, 0x78421E93,
        0x7A04A0CA, 0x7BC6CAFD, 0x6CBC2EB0, 0x6D7E4487, 0x6F38FADE, 0x6EFA90E9,
        0x6BB5866C, 0x6A77EC5B, 0x68315202, 0x69F33835, 0x62AF7F08, 0x636D153F,
        0x612BAB66, 0x60E9C151, 0x65A6D7D4, 0x6464BDE3, 0x662203BA, 0x67E0698D,
        0x48D7CB20, 0x4915A117, 0x4B531F4E, 0x4A917579, 0x4FDE63FC, 0x4E1C09CB,
        0x4C5AB792, 0x4D98DDA5, 0x46C49A98, 0x4706F0AF, 0x45404EF6, 0x448224C1,
        0x41CD3244, 0x400F5873, 0x4249E62A, 0x438B8C1D, 0x54F16850, 0x55330267,
        0x5775BC3E, 0x56B7D609, 0x53F8C08C, 0x523AAABB, 0x507C14E2, 0x51BE7ED5,
        0x5AE239E8, 0x5B2053DF, 0x5966ED86, 0x58A487B1, 0x5DEB9134, 0x5C29FB03,
        0x5E6F455A, 0x5FAD2F6D, 0xE1351B80, 0xE0F771B7, 0xE2B1CFEE, 0xE373A5D9,
        0xE63CB35C, 0xE7FED96B, 0xE5B86732, 0xE47A0D05, 0xEF264A38, 0xEEE4200F,
        0xECA29E56, 0xED60F461, 0xE82FE2E4, 0xE9ED88D3, 0xEBAB368A, 0xEA695CBD,
        0xFD13B8F0, 0xFCD1D2C7, 0xFE976C9E, 0xFF5506A9, 0xFA1A102C, 0xFBD87A1B,
        0xF99EC442, 0xF85CAE75, 0xF300E948, 0xF2C2837F, 0xF0843D26, 0xF1465711,
        0xF4094194, 0xF5CB2BA3, 0xF78D95FA, 0xF64FFFCD, 0xD9785D60, 0xD8BA3757,
        0xDAFC890E, 0xDB3EE339, 0xDE71F5BC, 0xDFB39F8B, 0xDDF521D2, 0xDC374BE5,
        0xD76B0CD8, 0xD6A966EF, 0xD4EFD8B6, 0xD52DB281, 0xD062A404, 0xD1A0CE33,
        0xD3E6706A, 0xD2241A5D, 0xC55EFE10, 0xC49C9427, 0xC6DA2A7E, 0xC7184049,
        0xC25756CC, 0xC3953CFB, 0xC1D382A2, 0xC011E895, 0xCB4DAFA8, 0xCA8FC59F,
        0xC8C97BC6, 0xC90B11F1, 0xCC440774, 0xCD866D43, 0xCFC0D31A, 0xCE02B92D,
        0x91AF9640, 0x906DFC77, 0x922B422E, 0x93E92819, 0x96A63E9C, 0x976454AB,
        0x9522EAF2, 0x94E080C5, 0x9FBCC7F8, 0x9E7EADCF, 0x9C381396, 0x9DFA79A1,
        0x98B56F24, 0x99770513, 0x9B31BB4A, 0x9AF3D17D, 0x8D893530, 0x8C4B5F07,
        0x8E0DE15E, 0x8FCF8B69, 0x8A809DEC, 0x8B42F7DB, 0x89044982, 0x88C623B5,
        0x839A6488, 0x82580EBF, 0x801EB0E6, 0x81DCDAD1, 0x8493CC54, 0x8551A663,
        0x8717183A, 0x86D5720D, 0xA9E2D0A0, 0xA820BA97, 0xAA6604CE, 0xABA46EF9,
        0xAEEB787C, 0xAF29124B, 0xAD6FAC12, 0xACADC625, 0xA7F18118, 0xA633EB2F,
        0xA4755576, 0xA5B73F41, 0xA0F829C4, 0xA13A43F3, 0xA37CFDAA, 0xA2BE979D,
        0xB5C473D0, 0xB40619E7, 0xB640A7BE, 0xB782CD89, 0xB2CDDB0C, 0xB30FB13B,
        0xB1490F62, 0xB08B6555, 0xBBD72268, 0xBA15485F, 0xB853F606, 0xB9919C31,
        0xBCDE8AB4, 0xBD1CE083, 0xBF5A5EDA, 0xBE9834ED,
    },

    {
        0x00000000, 0xB8BC6765, 0xAA09C88B, 0x12B5AFEE, 0x8F629757, 0x37DEF032,
        0x256B5FDC, 0x9DD738B9, 0xC5B428EF, 0x7D084F8A, 0x6FBDE064, 0xD7018701,
        0x4AD6BFB8, 0xF26AD8DD, 0xE0DF7733, 0x58631056, 0x5019579F, 0xE8A530FA,
        0xFA109F14, 0x42ACF871, 0xDF7BC0C8, 0x67C7A7AD, 0x75720843, 0xCDCE6F26,
        0x95AD7F70, 0x2D111815, 0x3FA4B7FB, 0x8718D09E, 0x1ACFE827, 0xA2738F42,
        0xB0C620AC, 0x087A47C9, 0xA032AF3E, 0x188EC85B, 0x0A3B67B5, 0xB28700D0,
        0x2F503869, 0x97EC5F0C, 0x8559F0E2, 0x3DE59787, 0x658687D1, 0xDD3AE0B4,
        0xCF8F4F5A, 0x7733283F, 0xEAE41086, 0x525877E3, 0x40EDD80D, 0xF851BF68,
        0xF02BF8A1, 0x48979FC4, 0x5A22302A, 0xE29E574F, 0x7F496FF6, 0xC7F50893,
        0xD540A77D, 0x6DFCC018, 0x359FD04E, 0x8D23B72B, 0x9F9618C5, 0x272A7FA0,
        0xBAFD4719, 0x0241207C, 0x10F48F92, 0xA848E8F7, 0x9B14583D, 0x23A83F58,
        0x311D90B6, 0x89A1F7D3, 0x1476CF6A, 0xACCAA80F, 0xBE7F07E1, 0x06C36084,
        0x5EA070D2, 0xE61C17B7, 0xF4A9B859, 0x4C15DF3C, 0xD1C2E785, 0x697E80E0,
        0x7BCB2F0E, 0xC377486B, 0xCB0D0FA2, 0x73B168C7, 0x6104C729, 0xD9B8A04C,
        0x446F98F5, 0xFCD3FF90, 0xEE66507E, 0x56DA371B, 0x0EB9274D, 0xB6054028,
        0xA4B0EFC6, 0x1C0C88A3, 0x81DBB01A, 0x3967D77F, 0x2BD27891, 0x936E1FF4,
        0x3B26F703, 0x839A9066, 0x912F3F88, 0x299358ED, 0xB4446054, 0x0CF80731,
        0x1E4DA8DF, 0xA6F1CFBA, 0xFE92DFEC, 0x462EB889, 0x549B1767, 0xEC277002,
        0x71F048BB, 0xC94C2FDE, 0xDBF98030, 0x6345E755, 0x6B3FA09C, 0xD383C7F9,
        0xC1366817, 0x798A0F72, 0xE45D37CB, 0x5CE150AE, 0x4E54FF40, 0xF6E89825,
        0xAE8B8873, 0x1637EF16, 0x048240F8, 0xBC3E279D, 0x21E91F24, 0x99557841,
        0x8BE0D7AF, 0x335CB0CA, 0xED59B63B, 0x55E5D15E, 0x47507EB0, 0xFFEC19D5,
        0x623B216C, 0xDA874609, 0xC832E9E7, 0x708E8E82, 0x28ED9ED4, 0x9051F9B1,
        0x82E4565F, 0x3A58313A, 0xA78F0983, 0x1F336EE6, 0x0D86C108, 0xB53AA66D,
        0xBD40E1A4, 0x05FC86C1, 0x1749292F, 0xAFF54E4A, 0x322276F3, 0x8A9E1196,
        0x982BBE78, 0x2097D91D, 0x78F4C94B, 0xC048AE2E, 0xD2FD01C0, 0x6A4166A5,
        0xF7965E1C, 0x4F2A3979, 0x5D9F9697, 0xE523F1F2, 0x4D6B1905, 0xF5D77E60,
        0xE762D18E, 0x5FDEB6EB, 0xC2098E52, 0x7AB5E937, 0x680046D9, 0xD0BC21BC,
        0x88DF31EA, 0x3063568F, 0x22D6F961, 0x9A6A9E04, 0x07BDA6BD, 0xBF01C1D8,
        0xADB46E36, 0x15080953, 0x1D724E9A, 0xA5CE29FF, 0xB77B8611, 0x0FC7E174,
        0x9210D9CD, 0x2AACBEA8, 0x38191146, 0x80A57623, 0xD8C66675, 0x607A0110,
        0x72CFAEFE, 0xCA73C99B, 0x57A4F122, 0xEF189647, 0xFDAD39A9, 0x45115ECC,
        0x764DEE06, 0xCEF18963, 0xDC44268D, 0x64F841E8, 0xF92F7951, 0x41931E34,
        0x5326B1DA, 0xEB9AD6BF, 0xB3F9C6E9, 0x0B45A18C, 0x19F00E62, 0xA14C6907,
        0x3C9B51BE, 0x842736DB, 0x96929935, 0x2E2EFE50, 0x2654B999, 0x9EE8DEFC,
        0x8C5D7112, 0x34E11677, 0xA9362ECE, 0x118A49AB, 0x033FE645, 0xBB838120,
        0xE3E09176, 0x5B5CF613, 0x49E959FD, 0xF1553E98, 0x6C820621, 0xD43E6144,
        0xC68BCEAA, 0x7E37A9CF, 0xD67F4138, 0x6EC3265D, 0x7C7689B3, 0xC4CAEED6,
        0x591DD66F, 0xE1A1B10A, 0xF3141EE4, 0x4BA87981, 0x13CB69D7, 0xAB770EB2,
        0xB9C2A15C, 0x017EC639, 0x9CA9FE80, 0x241599E5, 0x36A0360B, 0x8E1C516E,
        0x866616A7, 0x3EDA71C2, 0x2C6FDE2C, 0x94D3B949, 0x090481F0, 0xB1B8E695,
        0xA30D497B, 0x1BB12E1E, 0x43D23E48, 0xFB6E592D, 0xE9DBF6C3, 0x516791A6,
        0xCCB0A91F, 0x740CCE7A, 0x66B96194, 0xDE0506F1,
    }
#endif // defined(CRC32_USE_LOOKUP_TABLE_SLICING_BY_4) ||
       // defined(CRC32_USE_LOOKUP_TABLE_SLICING_BY_8) ||
       // defined(CRC32_USE_LOOKUP_TABLE_SLICING_BY_16)
#if defined(CRC32_USE_LOOKUP_TABLE_SLICING_BY_8) ||                            \
    defined(CRC32_USE_LOOKUP_TABLE_SLICING_BY_16)
    // beyond this point only relevant for Slicing-by-8 and Slicing-by-16
    ,
    {
        0x00000000, 0x3D6029B0, 0x7AC05360, 0x47A07AD0, 0xF580A6C0, 0xC8E08F70,
        0x8F40F5A0, 0xB220DC10, 0x30704BC1, 0x0D106271, 0x4AB018A1, 0x77D03111,
        0xC5F0ED01, 0xF890C4B1, 0xBF30BE61, 0x825097D1, 0x60E09782, 0x5D80BE32,
        0x1A20C4E2, 0x2740ED52, 0x95603142, 0xA80018F2, 0xEFA06222, 0xD2C04B92,
        0x5090DC43, 0x6DF0F5F3, 0x2A508F23, 0x1730A693, 0xA5107A83, 0x98705333,
        0xDFD029E3, 0xE2B00053, 0xC1C12F04, 0xFCA106B4, 0xBB017C64, 0x866155D4,
        0x344189C4, 0x0921A074, 0x4E81DAA4, 0x73E1F314, 0xF1B164C5, 0xCCD14D75,
        0x8B7137A5, 0xB6111E15, 0x0431C205, 0x3951EBB5, 0x7EF19165, 0x4391B8D5,
        0xA121B886, 0x9C419136, 0xDBE1EBE6, 0xE681C256, 0x54A11E46, 0x69C137F6,
        0x2E614D26, 0x13016496, 0x9151F347, 0xAC31DAF7, 0xEB91A027, 0xD6F18997,
        0x64D15587, 0x59B17C37, 0x1E1106E7, 0x23712F57, 0x58F35849, 0x659371F9,
        0x22330B29, 0x1F532299, 0xAD73FE89, 0x9013D739, 0xD7B3ADE9, 0xEAD38459,
        0x68831388, 0x55E33A38, 0x124340E8, 0x2F236958, 0x9D03B548, 0xA0639CF8,
        0xE7C3E628, 0xDAA3CF98, 0x3813CFCB, 0x0573E67B, 0x42D39CAB, 0x7FB3B51B,
        0xCD93690B, 0xF0F340BB, 0xB7533A6B, 0x8A3313DB, 0x0863840A, 0x3503ADBA,
        0x72A3D76A, 0x4FC3FEDA, 0xFDE322CA, 0xC0830B7A, 0x872371AA, 0xBA43581A,
        0x9932774D, 0xA4525EFD, 0xE3F2242D, 0xDE920D9D, 0x6CB2D18D, 0x51D2F83D,
        0x167282ED, 0x2B12AB5D, 0xA9423C8C, 0x9422153C, 0xD3826FEC, 0xEEE2465C,
        0x5CC29A4C, 0x61A2B3FC, 0x2602C92C, 0x1B62E09C, 0xF9D2E0CF, 0xC4B2C97F,
        0x8312B3AF, 0xBE729A1F, 0x0C52460F, 0x31326FBF, 0x7692156F, 0x4BF23CDF,
        0xC9A2AB0E, 0xF4C282BE, 0xB362F86E, 0x8E02D1DE, 0x3C220DCE, 0x0142247E,
        0x46E25EAE, 0x7B82771E, 0xB1E6B092, 0x8C869922, 0xCB26E3F2, 0xF646CA42,
        0x44661652, 0x79063FE2, 0x3EA64532, 0x03C66C82, 0x8196FB53, 0xBCF6D2E3,
        0xFB56A833, 0xC6368183, 0x74165D93, 0x49767423, 0x0ED60EF3, 0x33B62743,
        0xD1062710, 0xEC660EA0, 0xABC67470, 0x96A65DC0, 0x248681D0, 0x19E6A860,
        0x5E46D2B0, 0x6326FB00, 0xE1766CD1, 0xDC164561, 0x9BB63FB1, 0xA6D61601,
        0x14F6CA11, 0x2996E3A1, 0x6E369971, 0x5356B0C1, 0x70279F96, 0x4D47B626,
        0x0AE7CCF6, 0x3787E546, 0x85A73956, 0xB8C710E6, 0xFF676A36, 0xC2074386,
        0x4057D457, 0x7D37FDE7, 0x3A978737, 0x07F7AE87, 0xB5D77297, 0x88B75B27,
        0xCF1721F7, 0xF2770847, 0x10C70814, 0x2DA721A4, 0x6A075B74, 0x576772C4,
        0xE547AED4, 0xD8278764, 0x9F87FDB4, 0xA2E7D404, 0x20B743D5, 0x1DD76A65,
        0x5A7710B5, 0x67173905, 0xD537E515, 0xE857CCA5, 0xAFF7B675, 0x92979FC5,
        0xE915E8DB, 0xD475C16B, 0x93D5BBBB, 0xAEB5920B, 0x1C954E1B, 0x21F567AB,
        0x66551D7B, 0x5B3534CB, 0xD965A31A, 0xE4058AAA, 0xA3A5F07A, 0x9EC5D9CA,
        0x2CE505DA, 0x11852C6A, 0x562556BA, 0x6B457F0A, 0x89F57F59, 0xB49556E9,
        0xF3352C39, 0xCE550589, 0x7C75D999, 0x4115F029, 0x06B58AF9, 0x3BD5A349,
        0xB9853498, 0x84E51D28, 0xC34567F8, 0xFE254E48, 0x4C059258, 0x7165BBE8,
        0x36C5C138, 0x0BA5E888, 0x28D4C7DF, 0x15B4EE6F, 0x521494BF, 0x6F74BD0F,
        0xDD54611F, 0xE03448AF, 0xA794327F, 0x9AF41BCF, 0x18A48C1E, 0x25C4A5AE,
        0x6264DF7E, 0x5F04F6CE, 0xED242ADE, 0xD044036E, 0x97E479BE, 0xAA84500E,
        0x4834505D, 0x755479ED, 0x32F4033D, 0x0F942A8D, 0xBDB4F69D, 0x80D4DF2D,
        0xC774A5FD, 0xFA148C4D, 0x78441B9C, 0x4524322C, 0x028448FC, 0x3FE4614C,
        0x8DC4BD5C, 0xB0A494EC, 0xF704EE3C, 0xCA64C78C,
    },

    {
        0x00000000, 0xCB5CD3A5, 0x4DC8A10B, 0x869472AE, 0x9B914216, 0x50CD91B3,
        0xD659E31D, 0x1D0530B8, 0xEC53826D, 0x270F51C8, 0xA19B2366, 0x6AC7F0C3,
        0x77C2C07B, 0xBC9E13DE, 0x3A0A6170, 0xF156B2D5, 0x03D6029B, 0xC88AD13E,
        0x4E1EA390, 0x85427035, 0x9847408D, 0x531B9328, 0xD58FE186, 0x1ED33223,
        0xEF8580F6, 0x24D95353, 0xA24D21FD, 0x6911F258, 0x7414C2E0, 0xBF481145,
        0x39DC63EB, 0xF280B04E, 0x07AC0536, 0xCCF0D693, 0x4A64A43D, 0x81387798,
        0x9C3D4720, 0x57619485, 0xD1F5E62B, 0x1AA9358E, 0xEBFF875B, 0x20A354FE,
        0xA6372650, 0x6D6BF5F5, 0x706EC54D, 0xBB3216E8, 0x3DA66446, 0xF6FAB7E3,
        0x047A07AD, 0xCF26D408, 0x49B2A6A6, 0x82EE7503, 0x9FEB45BB, 0x54B7961E,
        0xD223E4B0, 0x197F3715, 0xE82985C0, 0x23755665, 0xA5E124CB, 0x6EBDF76E,
        0x73B8C7D6, 0xB8E41473, 0x3E7066DD, 0xF52CB578, 0x0F580A6C, 0xC404D9C9,
        0x4290AB67, 0x89CC78C2, 0x94C9487A, 0x5F959BDF, 0xD901E971, 0x125D3AD4,
        0xE30B8801, 0x28575BA4, 0xAEC3290A, 0x659FFAAF, 0x789ACA17, 0xB3C619B2,
        0x35526B1C, 0xFE0EB8B9, 0x0C8E08F7, 0xC7D2DB52, 0x4146A9FC, 0x8A1A7A59,
        0x971F4AE1, 0x5C439944, 0xDAD7EBEA, 0x118B384F, 0xE0DD8A9A, 0x2B81593F,
        0xAD152B91, 0x6649F834, 0x7B4CC88C, 0xB0101B29, 0x36846987, 0xFDD8BA22,
        0x08F40F5A, 0xC3A8DCFF, 0x453CAE51, 0x8E607DF4, 0x93654D4C, 0x58399EE9,
        0xDEADEC47, 0x15F13FE2, 0xE4A78D37, 0x2FFB5E92, 0xA96F2C3C, 0x6233FF99,
        0x7F36CF21, 0xB46A1C84, 0x32FE6E2A, 0xF9A2BD8F, 0x0B220DC1, 0xC07EDE64,
        0x46EAACCA, 0x8DB67F6F, 0x90B34FD7, 0x5BEF9C72, 0xDD7BEEDC, 0x16273D79,
        0xE7718FAC, 0x2C2D5C09, 0xAAB92EA7, 0x61E5FD02, 0x7CE0CDBA, 0xB7BC1E1F,
        0x31286CB1, 0xFA74BF14, 0x1EB014D8, 0xD5ECC77D, 0x5378B5D3, 0x98246676,
        0x852156CE, 0x4E7D856B, 0xC8E9F7C5, 0x03B52460, 0xF2E396B5, 0x39BF4510,
        0xBF2B37BE, 0x7477E41B, 0x6972D4A3, 0xA22E0706, 0x24BA75A8, 0xEFE6A60D,
        0x1D661643, 0xD63AC5E6, 0x50AEB748, 0x9BF264ED, 0x86F75455, 0x4DAB87F0,
        0xCB3FF55E, 0x006326FB, 0xF135942E, 0x3A69478B, 0xBCFD3525, 0x77A1E680,
        0x6AA4D638, 0xA1F8059D, 0x276C7733, 0xEC30A496, 0x191C11EE, 0xD240C24B,
        0x54D4B0E5, 0x9F886340, 0x828D53F8, 0x49D1805D, 0xCF45F2F3, 0x04192156,
        0xF54F9383, 0x3E134026, 0xB8873288, 0x73DBE12D, 0x6EDED195, 0xA5820230,
        0x2316709E, 0xE84AA33B, 0x1ACA1375, 0xD196C0D0, 0x5702B27E, 0x9C5E61DB,
        0x815B5163, 0x4A0782C6, 0xCC93F068, 0x07CF23CD, 0xF6999118, 0x3DC542BD,
        0xBB513013, 0x700DE3B6, 0x6D08D30E, 0xA65400AB, 0x20C07205, 0xEB9CA1A0,
        0x11E81EB4, 0xDAB4CD11, 0x5C20BFBF, 0x977C6C1A, 0x8A795CA2, 0x41258F07,
        0xC7B1FDA9, 0x0CED2E0C, 0xFDBB9CD9, 0x36E74F7C, 0xB0733DD2, 0x7B2FEE77,
        0x662ADECF, 0xAD760D6A, 0x2BE27FC4, 0xE0BEAC61, 0x123E1C2F, 0xD962CF8A,
        0x5FF6BD24, 0x94AA6E81, 0x89AF5E39, 0x42F38D9C, 0xC467FF32, 0x0F3B2C97,
        0xFE6D9E42, 0x35314DE7, 0xB3A53F49, 0x78F9ECEC, 0x65FCDC54, 0xAEA00FF1,
        0x28347D5F, 0xE368AEFA, 0x16441B82, 0xDD18C827, 0x5B8CBA89, 0x90D0692C,
        0x8DD55994, 0x46898A31, 0xC01DF89F, 0x0B412B3A, 0xFA1799EF, 0x314B4A4A,
        0xB7DF38E4, 0x7C83EB41, 0x6186DBF9, 0xAADA085C, 0x2C4E7AF2, 0xE712A957,
        0x15921919, 0xDECECABC, 0x585AB812, 0x93066BB7, 0x8E035B0F, 0x455F88AA,
        0xC3CBFA04, 0x089729A1, 0xF9C19B74, 0x329D48D1, 0xB4093A7F, 0x7F55E9DA,
        0x6250D962, 0xA90C0AC7, 0x2F987869, 0xE4C4ABCC,
    },

    {
        0x00000000, 0xA6770BB4, 0x979F1129, 0x31E81A9D, 0xF44F2413, 0x52382FA7,
        0x63D0353A, 0xC5A73E8E, 0x33EF4E67, 0x959845D3, 0xA4705F4E, 0x020754FA,
        0xC7A06A74, 0x61D761C0, 0x503F7B5D, 0xF64870E9, 0x67DE9CCE, 0xC1A9977A,
        0xF0418DE7, 0x56368653, 0x9391B8DD, 0x35E6B369, 0x040EA9F4, 0xA279A240,
        0x5431D2A9, 0xF246D91D, 0xC3AEC380, 0x65D9C834, 0xA07EF6BA, 0x0609FD0E,
        0x37E1E793, 0x9196EC27, 0xCFBD399C, 0x69CA3228, 0x582228B5, 0xFE552301,
        0x3BF21D8F, 0x9D85163B, 0xAC6D0CA6, 0x0A1A0712, 0xFC5277FB, 0x5A257C4F,
        0x6BCD66D2, 0xCDBA6D66, 0x081D53E8, 0xAE6A585C, 0x9F8242C1, 0x39F54975,
        0xA863A552, 0x0E14AEE6, 0x3FFCB47B, 0x998BBFCF, 0x5C2C8141, 0xFA5B8AF5,
        0xCBB39068, 0x6DC49BDC, 0x9B8CEB35, 0x3DFBE081, 0x0C13FA1C, 0xAA64F1A8,
        0x6FC3CF26, 0xC9B4C492, 0xF85CDE0F, 0x5E2BD5BB, 0x440B7579, 0xE27C7ECD,
        0xD3946450, 0x75E36FE4, 0xB044516A, 0x16335ADE, 0x27DB4043, 0x81AC4BF7,
        0x77E43B1E, 0xD19330AA, 0xE07B2A37, 0x460C2183, 0x83AB1F0D, 0x25DC14B9,
        0x14340E24, 0xB2430590, 0x23D5E9B7, 0x85A2E203, 0xB44AF89E, 0x123DF32A,
        0xD79ACDA4, 0x71EDC610, 0x4005DC8D, 0xE672D739, 0x103AA7D0, 0xB64DAC64,
        0x87A5B6F9, 0x21D2BD4D, 0xE47583C3, 0x42028877, 0x73EA92EA, 0xD59D995E,
        0x8BB64CE5, 0x2DC14751, 0x1C295DCC, 0xBA5E5678, 0x7FF968F6, 0xD98E6342,
        0xE86679DF, 0x4E11726B, 0xB8590282, 0x1E2E0936, 0x2FC613AB, 0x89B1181F,
        0x4C162691, 0xEA612D25, 0xDB8937B8, 0x7DFE3C0C, 0xEC68D02B, 0x4A1FDB9F,
        0x7BF7C102, 0xDD80CAB6, 0x1827F438, 0xBE50FF8C, 0x8FB8E511, 0x29CFEEA5,
        0xDF879E4C, 0x79F095F8, 0x48188F65, 0xEE6F84D1, 0x2BC8BA5F, 0x8DBFB1EB,
        0xBC57AB76, 0x1A20A0C2, 0x8816EAF2, 0x2E61E146, 0x1F89FBDB, 0xB9FEF06F,
        0x7C59CEE1, 0xDA2EC555, 0xEBC6DFC8, 0x4DB1D47C, 0xBBF9A495, 0x1D8EAF21,
        0x2C66B5BC, 0x8A11BE08, 0x4FB68086, 0xE9C18B32, 0xD82991AF, 0x7E5E9A1B,
        0xEFC8763C, 0x49BF7D88, 0x78576715, 0xDE206CA1, 0x1B87522F, 0xBDF0599B,
        0x8C184306, 0x2A6F48B2, 0xDC27385B, 0x7A5033EF, 0x4BB82972, 0xEDCF22C6,
        0x28681C48, 0x8E1F17FC, 0xBFF70D61, 0x198006D5, 0x47ABD36E, 0xE1DCD8DA,
        0xD034C247, 0x7643C9F3, 0xB3E4F77D, 0x1593FCC9, 0x247BE654, 0x820CEDE0,
        0x74449D09, 0xD23396BD, 0xE3DB8C20, 0x45AC8794, 0x800BB91A, 0x267CB2AE,
        0x1794A833, 0xB1E3A387, 0x20754FA0, 0x86024414, 0xB7EA5E89, 0x119D553D,
        0xD43A6BB3, 0x724D6007, 0x43A57A9A, 0xE5D2712E, 0x139A01C7, 0xB5ED0A73,
        0x840510EE, 0x22721B5A, 0xE7D525D4, 0x41A22E60, 0x704A34FD, 0xD63D3F49,
        0xCC1D9F8B, 0x6A6A943F, 0x5B828EA2, 0xFDF58516, 0x3852BB98, 0x9E25B02C,
        0xAFCDAAB1, 0x09BAA105, 0xFFF2D1EC, 0x5985DA58, 0x686DC0C5, 0xCE1ACB71,
        0x0BBDF5FF, 0xADCAFE4B, 0x9C22E4D6, 0x3A55EF62, 0xABC30345, 0x0DB408F1,
        0x3C5C126C, 0x9A2B19D8, 0x5F8C2756, 0xF9FB2CE2, 0xC813367F, 0x6E643DCB,
        0x982C4D22, 0x3E5B4696, 0x0FB35C0B, 0xA9C457BF, 0x6C636931, 0xCA146285,
        0xFBFC7818, 0x5D8B73AC, 0x03A0A617, 0xA5D7ADA3, 0x943FB73E, 0x3248BC8A,
        0xF7EF8204, 0x519889B0, 0x6070932D, 0xC6079899, 0x304FE870, 0x9638E3C4,
        0xA7D0F959, 0x01A7F2ED, 0xC400CC63, 0x6277C7D7, 0x539FDD4A, 0xF5E8D6FE,
        0x647E3AD9, 0xC209316D, 0xF3E12BF0, 0x55962044, 0x90311ECA, 0x3646157E,
        0x07AE0FE3, 0xA1D90457, 0x579174BE, 0xF1E67F0A, 0xC00E6597, 0x66796E23,
        0xA3DE50AD, 0x05A95B19, 0x34414184, 0x92364A30,
    },

    {
        0x00000000, 0xCCAA009E, 0x4225077D, 0x8E8F07E3, 0x844A0EFA, 0x48E00E64,
        0xC66F0987, 0x0AC50919, 0xD3E51BB5, 0x1F4F1B2B, 0x91C01CC8, 0x5D6A1C56,
        0x57AF154F, 0x9B0515D1, 0x158A1232, 0xD92012AC, 0x7CBB312B, 0xB01131B5,
        0x3E9E3656, 0xF23436C8, 0xF8F13FD1, 0x345B3F4F, 0xBAD438AC, 0x767E3832,
        0xAF5E2A9E, 0x63F42A00, 0xED7B2DE3, 0x21D12D7D, 0x2B142464, 0xE7BE24FA,
        0x69312319, 0xA59B2387, 0xF9766256, 0x35DC62C8, 0xBB53652B, 0x77F965B5,
        0x7D3C6CAC, 0xB1966C32, 0x3F196BD1, 0xF3B36B4F, 0x2A9379E3, 0xE639797D,
        0x68B67E9E, 0xA41C7E00, 0xAED97719, 0x62737787, 0xECFC7064, 0x205670FA,
        0x85CD537D, 0x496753E3, 0xC7E85400, 0x0B42549E, 0x01875D87, 0xCD2D5D19,
        0x43A25AFA, 0x8F085A64, 0x562848C8, 0x9A824856, 0x140D4FB5, 0xD8A74F2B,
        0xD2624632, 0x1EC846AC, 0x9047414F, 0x5CED41D1, 0x299DC2ED, 0xE537C273,
        0x6BB8C590, 0xA712C50E, 0xADD7CC17, 0x617DCC89, 0xEFF2CB6A, 0x2358CBF4,
        0xFA78D958, 0x36D2D9C6, 0xB85DDE25, 0x74F7DEBB, 0x7E32D7A2, 0xB298D73C,
        0x3C17D0DF, 0xF0BDD041, 0x5526F3C6, 0x998CF358, 0x1703F4BB, 0xDBA9F425,
        0xD16CFD3C, 0x1DC6FDA2, 0x9349FA41, 0x5FE3FADF, 0x86C3E873, 0x4A69E8ED,
        0xC4E6EF0E, 0x084CEF90, 0x0289E689, 0xCE23E617, 0x40ACE1F4, 0x8C06E16A,
        0xD0EBA0BB, 0x1C41A025, 0x92CEA7C6, 0x5E64A758, 0x54A1AE41, 0x980BAEDF,
        0x1684A93C, 0xDA2EA9A2, 0x030EBB0E, 0xCFA4BB90, 0x412BBC73, 0x8D81BCED,
        0x8744B5F4, 0x4BEEB56A, 0xC561B289, 0x09CBB217, 0xAC509190, 0x60FA910E,
        0xEE7596ED, 0x22DF9673, 0x281A9F6A, 0xE4B09FF4, 0x6A3F9817, 0xA6959889,
        0x7FB58A25, 0xB31F8ABB, 0x3D908D58, 0xF13A8DC6, 0xFBFF84DF, 0x37558441,
        0xB9DA83A2, 0x7570833C, 0x533B85DA, 0x9F918544, 0x111E82A7, 0xDDB48239,
        0xD7718B20, 0x1BDB8BBE, 0x95548C5D, 0x59FE8CC3, 0x80DE9E6F, 0x4C749EF1,
        0xC2FB9912, 0x0E51998C, 0x04949095, 0xC83E900B, 0x46B197E8, 0x8A1B9776,
        0x2F80B4F1, 0xE32AB46F, 0x6DA5B38C, 0xA10FB312, 0xABCABA0B, 0x6760BA95,
        0xE9EFBD76, 0x2545BDE8, 0xFC65AF44, 0x30CFAFDA, 0xBE40A839, 0x72EAA8A7,
        0x782FA1BE, 0xB485A120, 0x3A0AA6C3, 0xF6A0A65D, 0xAA4DE78C, 0x66E7E712,
        0xE868E0F1, 0x24C2E06F, 0x2E07E976, 0xE2ADE9E8, 0x6C22EE0B, 0xA088EE95,
        0x79A8FC39, 0xB502FCA7, 0x3B8DFB44, 0xF727FBDA, 0xFDE2F2C3, 0x3148F25D,
        0xBFC7F5BE, 0x736DF520, 0xD6F6D6A7, 0x1A5CD639, 0x94D3D1DA, 0x5879D144,
        0x52BCD85D, 0x9E16D8C3, 0x1099DF20, 0xDC33DFBE, 0x0513CD12, 0xC9B9CD8C,
        0x4736CA6F, 0x8B9CCAF1, 0x8159C3E8, 0x4DF3C376, 0xC37CC495, 0x0FD6C40B,
        0x7AA64737, 0xB60C47A9, 0x3883404A, 0xF42940D4, 0xFEEC49CD, 0x32464953,
        0xBCC94EB0, 0x70634E2E, 0xA9435C82, 0x65E95C1C, 0xEB665BFF, 0x27CC5B61,
        0x2D095278, 0xE1A352E6, 0x6F2C5505, 0xA386559B, 0x061D761C, 0xCAB77682,
        0x44387161, 0x889271FF, 0x825778E6, 0x4EFD7878, 0xC0727F9B, 0x0CD87F05,
        0xD5F86DA9, 0x19526D37, 0x97DD6AD4, 0x5B776A4A, 0x51B26353, 0x9D1863CD,
        0x1397642E, 0xDF3D64B0, 0x83D02561, 0x4F7A25FF, 0xC1F5221C, 0x0D5F2282,
        0x079A2B9B, 0xCB302B05, 0x45BF2CE6, 0x89152C78, 0x50353ED4, 0x9C9F3E4A,
        0x121039A9, 0xDEBA3937, 0xD47F302E, 0x18D530B0, 0x965A3753, 0x5AF037CD,
        0xFF6B144A, 0x33C114D4, 0xBD4E1337, 0x71E413A9, 0x7B211AB0, 0xB78B1A2E,
        0x39041DCD, 0xF5AE1D53, 0x2C8E0FFF, 0xE0240F61, 0x6EAB0882, 0xA201081C,
        0xA8C40105, 0x646E019B, 0xEAE10678, 0x264B06E6,
    }
#endif // CRC32_USE_LOOKUP_TABLE_SLICING_BY_8 ||
       // CRC32_USE_LOOKUP_TABLE_SLICING_BY_16
#ifdef CRC32_USE_LOOKUP_TABLE_SLICING_BY_16
    // beyond this point only relevant for Slicing-by-16
    ,
    {
        0x00000000, 0x177B1443, 0x2EF62886, 0x398D3CC5, 0x5DEC510C, 0x4A97454F,
        0x731A798A, 0x64616DC9, 0xBBD8A218, 0xACA3B65B, 0x952E8A9E, 0x82559EDD,
        0xE634F314, 0xF14FE757, 0xC8C2DB92, 0xDFB9CFD1, 0xACC04271, 0xBBBB5632,
        0x82366AF7, 0x954D7EB4, 0xF12C137D, 0xE657073E, 0xDFDA3BFB, 0xC8A12FB8,
        0x1718E069, 0x0063F42A, 0x39EEC8EF, 0x2E95DCAC, 0x4AF4B165, 0x5D8FA526,
        0x640299E3, 0x73798DA0, 0x82F182A3, 0x958A96E0, 0xAC07AA25, 0xBB7CBE66,
        0xDF1DD3AF, 0xC866C7EC, 0xF1EBFB29, 0xE690EF6A, 0x392920BB, 0x2E5234F8,
        0x17DF083D, 0x00A41C7E, 0x64C571B7, 0x73BE65F4, 0x4A335931, 0x5D484D72,
        0x2E31C0D2, 0x394AD491, 0x00C7E854, 0x17BCFC17, 0x73DD91DE, 0x64A6859D,
        0x5D2BB958, 0x4A50AD1B, 0x95E962CA, 0x82927689, 0xBB1F4A4C, 0xAC645E0F,
        0xC80533C6, 0xDF7E2785, 0xE6F31B40, 0xF1880F03, 0xDE920307, 0xC9E91744,
        0xF0642B81, 0xE71F3FC2, 0x837E520B, 0x94054648, 0xAD887A8D, 0xBAF36ECE,
        0x654AA11F, 0x7231B55C, 0x4BBC8999, 0x5CC79DDA, 0x38A6F013, 0x2FDDE450,
        0x1650D895, 0x012BCCD6, 0x72524176, 0x65295535, 0x5CA469F0, 0x4BDF7DB3,
        0x2FBE107A, 0x38C50439, 0x014838FC, 0x16332CBF, 0xC98AE36E, 0xDEF1F72D,
        0xE77CCBE8, 0xF007DFAB, 0x9466B262, 0x831DA621, 0xBA909AE4, 0xADEB8EA7,
        0x5C6381A4, 0x4B1895E7, 0x7295A922, 0x65EEBD61, 0x018FD0A8, 0x16F4C4EB,
        0x2F79F82E, 0x3802EC6D, 0xE7BB23BC, 0xF0C037FF, 0xC94D0B3A, 0xDE361F79,
        0xBA5772B0, 0xAD2C66F3, 0x94A15A36, 0x83DA4E75, 0xF0A3C3D5, 0xE7D8D796,
        0xDE55EB53, 0xC92EFF10, 0xAD4F92D9, 0xBA34869A, 0x83B9BA5F, 0x94C2AE1C,
        0x4B7B61CD, 0x5C00758E, 0x658D494B, 0x72F65D08, 0x169730C1, 0x01EC2482,
        0x38611847, 0x2F1A0C04, 0x6655004F, 0x712E140C, 0x48A328C9, 0x5FD83C8A,
        0x3BB95143, 0x2CC24500, 0x154F79C5, 0x02346D86, 0xDD8DA257, 0xCAF6B614,
        0xF37B8AD1, 0xE4009E92, 0x8061F35B, 0x971AE718, 0xAE97DBDD, 0xB9ECCF9E,
        0xCA95423E, 0xDDEE567D, 0xE4636AB8, 0xF3187EFB, 0x97791332, 0x80020771,
        0xB98F3BB4, 0xAEF42FF7, 0x714DE026, 0x6636F465, 0x5FBBC8A0, 0x48C0DCE3,
        0x2CA1B12A, 0x3BDAA569, 0x025799AC, 0x152C8DEF, 0xE4A482EC, 0xF3DF96AF,
        0xCA52AA6A, 0xDD29BE29, 0xB948D3E0, 0xAE33C7A3, 0x97BEFB66, 0x80C5EF25,
        0x5F7C20F4, 0x480734B7, 0x718A0872, 0x66F11C31, 0x029071F8, 0x15EB65BB,
        0x2C66597E, 0x3B1D4D3D, 0x4864C09D, 0x5F1FD4DE, 0x6692E81B, 0x71E9FC58,
        0x15889191, 0x02F385D2, 0x3B7EB917, 0x2C05AD54, 0xF3BC6285, 0xE4C776C6,
        0xDD4A4A03, 0xCA315E40, 0xAE503389, 0xB92B27CA, 0x80A61B0F, 0x97DD0F4C,
        0xB8C70348, 0xAFBC170B, 0x96312BCE, 0x814A3F8D, 0xE52B5244, 0xF2504607,
        0xCBDD7AC2, 0xDCA66E81, 0x031FA150, 0x1464B513, 0x2DE989D6, 0x3A929D95,
        0x5EF3F05C, 0x4988E41F, 0x7005D8DA, 0x677ECC99, 0x14074139, 0x037C557A,
        0x3AF169BF, 0x2D8A7DFC, 0x49EB1035, 0x5E900476, 0x671D38B3, 0x70662CF0,
        0xAFDFE321, 0xB8A4F762, 0x8129CBA7, 0x9652DFE4, 0xF233B22D, 0xE548A66E,
        0xDCC59AAB, 0xCBBE8EE8, 0x3A3681EB, 0x2D4D95A8, 0x14C0A96D, 0x03BBBD2E,
        0x67DAD0E7, 0x70A1C4A4, 0x492CF861, 0x5E57EC22, 0x81EE23F3, 0x969537B0,
        0xAF180B75, 0xB8631F36, 0xDC0272FF, 0xCB7966BC, 0xF2F45A79, 0xE58F4E3A,
        0x96F6C39A, 0x818DD7D9, 0xB800EB1C, 0xAF7BFF5F, 0xCB1A9296, 0xDC6186D5,
        0xE5ECBA10, 0xF297AE53, 0x2D2E6182, 0x3A5575C1, 0x03D84904, 0x14A35D47,
        0x70C2308E, 0x67B924CD, 0x5E341808, 0x494F0C4B,
    },

    {
        0x00000000, 0xEFC26B3E, 0x04F5D03D, 0xEB37BB03, 0x09EBA07A, 0xE629CB44,
        0x0D1E7047, 0xE2DC1B79, 0x13D740F4, 0xFC152BCA, 0x172290C9, 0xF8E0FBF7,
        0x1A3CE08E, 0xF5FE8BB0, 0x1EC930B3, 0xF10B5B8D, 0x27AE81E8, 0xC86CEAD6,
        0x235B51D5, 0xCC993AEB, 0x2E452192, 0xC1874AAC, 0x2AB0F1AF, 0xC5729A91,
        0x3479C11C, 0xDBBBAA22, 0x308C1121, 0xDF4E7A1F, 0x3D926166, 0xD2500A58,
        0x3967B15B, 0xD6A5DA65, 0x4F5D03D0, 0xA09F68EE, 0x4BA8D3ED, 0xA46AB8D3,
        0x46B6A3AA, 0xA974C894, 0x42437397, 0xAD8118A9, 0x5C8A4324, 0xB348281A,
        0x587F9319, 0xB7BDF827, 0x5561E35E, 0xBAA38860, 0x51943363, 0xBE56585D,
        0x68F38238, 0x8731E906, 0x6C065205, 0x83C4393B, 0x61182242, 0x8EDA497C,
        0x65EDF27F, 0x8A2F9941, 0x7B24C2CC, 0x94E6A9F2, 0x7FD112F1, 0x901379CF,
        0x72CF62B6, 0x9D0D0988, 0x763AB28B, 0x99F8D9B5, 0x9EBA07A0, 0x71786C9E,
        0x9A4FD79D, 0x758DBCA3, 0x9751A7DA, 0x7893CCE4, 0x93A477E7, 0x7C661CD9,
        0x8D6D4754, 0x62AF2C6A, 0x89989769, 0x665AFC57, 0x8486E72E, 0x6B448C10,
        0x80733713, 0x6FB15C2D, 0xB9148648, 0x56D6ED76, 0xBDE15675, 0x52233D4B,
        0xB0FF2632, 0x5F3D4D0C, 0xB40AF60F, 0x5BC89D31, 0xAAC3C6BC, 0x4501AD82,
        0xAE361681, 0x41F47DBF, 0xA32866C6, 0x4CEA0DF8, 0xA7DDB6FB, 0x481FDDC5,
        0xD1E70470, 0x3E256F4E, 0xD512D44D, 0x3AD0BF73, 0xD80CA40A, 0x37CECF34,
        0xDCF97437, 0x333B1F09, 0xC2304484, 0x2DF22FBA, 0xC6C594B9, 0x2907FF87,
        0xCBDBE4FE, 0x24198FC0, 0xCF2E34C3, 0x20EC5FFD, 0xF6498598, 0x198BEEA6,
        0xF2BC55A5, 0x1D7E3E9B, 0xFFA225E2, 0x10604EDC, 0xFB57F5DF, 0x14959EE1,
        0xE59EC56C, 0x0A5CAE52, 0xE16B1551, 0x0EA97E6F, 0xEC756516, 0x03B70E28,
        0xE880B52B, 0x0742DE15, 0xE6050901, 0x09C7623F, 0xE2F0D93C, 0x0D32B202,
        0xEFEEA97B, 0x002CC245, 0xEB1B7946, 0x04D91278, 0xF5D249F5, 0x1A1022CB,
        0xF12799C8, 0x1EE5F2F6, 0xFC39E98F, 0x13FB82B1, 0xF8CC39B2, 0x170E528C,
        0xC1AB88E9, 0x2E69E3D7, 0xC55E58D4, 0x2A9C33EA, 0xC8402893, 0x278243AD,
        0xCCB5F8AE, 0x23779390, 0xD27CC81D, 0x3DBEA323, 0xD6891820, 0x394B731E,
        0xDB976867, 0x34550359, 0xDF62B85A, 0x30A0D364, 0xA9580AD1, 0x469A61EF,
        0xADADDAEC, 0x426FB1D2, 0xA0B3AAAB, 0x4F71C195, 0xA4467A96, 0x4B8411A8,
        0xBA8F4A25, 0x554D211B, 0xBE7A9A18, 0x51B8F126, 0xB364EA5F, 0x5CA68161,
        0xB7913A62, 0x5853515C, 0x8EF68B39, 0x6134E007, 0x8A035B04, 0x65C1303A,
        0x871D2B43, 0x68DF407D, 0x83E8FB7E, 0x6C2A9040, 0x9D21CBCD, 0x72E3A0F3,
        0x99D41BF0, 0x761670CE, 0x94CA6BB7, 0x7B080089, 0x903FBB8A, 0x7FFDD0B4,
        0x78BF0EA1, 0x977D659F, 0x7C4ADE9C, 0x9388B5A2, 0x7154AEDB, 0x9E96C5E5,
        0x75A17EE6, 0x9A6315D8, 0x6B684E55, 0x84AA256B, 0x6F9D9E68, 0x805FF556,
        0x6283EE2F, 0x8D418511, 0x66763E12, 0x89B4552C, 0x5F118F49, 0xB0D3E477,
        0x5BE45F74, 0xB426344A, 0x56FA2F33, 0xB938440D, 0x520FFF0E, 0xBDCD9430,
        0x4CC6CFBD, 0xA304A483, 0x48331F80, 0xA7F174BE, 0x452D6FC7, 0xAAEF04F9,
        0x41D8BFFA, 0xAE1AD4C4, 0x37E20D71, 0xD820664F, 0x3317DD4C, 0xDCD5B672,
        0x3E09AD0B, 0xD1CBC635, 0x3AFC7D36, 0xD53E1608, 0x24354D85, 0xCBF726BB,
        0x20C09DB8, 0xCF02F686, 0x2DDEEDFF, 0xC21C86C1, 0x292B3DC2, 0xC6E956FC,
        0x104C8C99, 0xFF8EE7A7, 0x14B95CA4, 0xFB7B379A, 0x19A72CE3, 0xF66547DD,
        0x1D52FCDE, 0xF29097E0, 0x039BCC6D, 0xEC59A753, 0x076E1C50, 0xE8AC776E,
        0x0A706C17, 0xE5B20729, 0x0E85BC2A, 0xE147D714,
    },

    {
        0x00000000, 0xC18EDFC0, 0x586CB9C1, 0x99E26601, 0xB0D97382, 0x7157AC42,
        0xE8B5CA43, 0x293B1583, 0xBAC3E145, 0x7B4D3E85, 0xE2AF5884, 0x23218744,
        0x0A1A92C7, 0xCB944D07, 0x52762B06, 0x93F8F4C6, 0xAEF6C4CB, 0x6F781B0B,
        0xF69A7D0A, 0x3714A2CA, 0x1E2FB749, 0xDFA16889, 0x46430E88, 0x87CDD148,
        0x1435258E, 0xD5BBFA4E, 0x4C599C4F, 0x8DD7438F, 0xA4EC560C, 0x656289CC,
        0xFC80EFCD, 0x3D0E300D, 0x869C8FD7, 0x47125017, 0xDEF03616, 0x1F7EE9D6,
        0x3645FC55, 0xF7CB2395, 0x6E294594, 0xAFA79A54, 0x3C5F6E92, 0xFDD1B152,
        0x6433D753, 0xA5BD0893, 0x8C861D10, 0x4D08C2D0, 0xD4EAA4D1, 0x15647B11,
        0x286A4B1C, 0xE9E494DC, 0x7006F2DD, 0xB1882D1D, 0x98B3389E, 0x593DE75E,
        0xC0DF815F, 0x01515E9F, 0x92A9AA59, 0x53277599, 0xCAC51398, 0x0B4BCC58,
        0x2270D9DB, 0xE3FE061B, 0x7A1C601A, 0xBB92BFDA, 0xD64819EF, 0x17C6C62F,
        0x8E24A02E, 0x4FAA7FEE, 0x66916A6D, 0xA71FB5AD, 0x3EFDD3AC, 0xFF730C6C,
        0x6C8BF8AA, 0xAD05276A, 0x34E7416B, 0xF5699EAB, 0xDC528B28, 0x1DDC54E8,
        0x843E32E9, 0x45B0ED29, 0x78BEDD24, 0xB93002E4, 0x20D264E5, 0xE15CBB25,
        0xC867AEA6, 0x09E97166, 0x900B1767, 0x5185C8A7, 0xC27D3C61, 0x03F3E3A1,
        0x9A1185A0, 0x5B9F5A60, 0x72A44FE3, 0xB32A9023, 0x2AC8F622, 0xEB4629E2,
        0x50D49638, 0x915A49F8, 0x08B82FF9, 0xC936F039, 0xE00DE5BA, 0x21833A7A,
        0xB8615C7B, 0x79EF83BB, 0xEA17777D, 0x2B99A8BD, 0xB27BCEBC, 0x73F5117C,
        0x5ACE04FF, 0x9B40DB3F, 0x02A2BD3E, 0xC32C62FE, 0xFE2252F3, 0x3FAC8D33,
        0xA64EEB32, 0x67C034F2, 0x4EFB2171, 0x8F75FEB1, 0x169798B0, 0xD7194770,
        0x44E1B3B6, 0x856F6C76, 0x1C8D0A77, 0xDD03D5B7, 0xF438C034, 0x35B61FF4,
        0xAC5479F5, 0x6DDAA635, 0x77E1359F, 0xB66FEA5F, 0x2F8D8C5E, 0xEE03539E,
        0xC738461D, 0x06B699DD, 0x9F54FFDC, 0x5EDA201C, 0xCD22D4DA, 0x0CAC0B1A,
        0x954E6D1B, 0x54C0B2DB, 0x7DFBA758, 0xBC757898, 0x25971E99, 0xE419C159,
        0xD917F154, 0x18992E94, 0x817B4895, 0x40F59755, 0x69CE82D6, 0xA8405D16,
        0x31A23B17, 0xF02CE4D7, 0x63D41011, 0xA25ACFD1, 0x3BB8A9D0, 0xFA367610,
        0xD30D6393, 0x1283BC53, 0x8B61DA52, 0x4AEF0592, 0xF17DBA48, 0x30F36588,
        0xA9110389, 0x689FDC49, 0x41A4C9CA, 0x802A160A, 0x19C8700B, 0xD846AFCB,
        0x4BBE5B0D, 0x8A3084CD, 0x13D2E2CC, 0xD25C3D0C, 0xFB67288F, 0x3AE9F74F,
        0xA30B914E, 0x62854E8E, 0x5F8B7E83, 0x9E05A143, 0x07E7C742, 0xC6691882,
        0xEF520D01, 0x2EDCD2C1, 0xB73EB4C0, 0x76B06B00, 0xE5489FC6, 0x24C64006,
        0xBD242607, 0x7CAAF9C7, 0x5591EC44, 0x941F3384, 0x0DFD5585, 0xCC738A45,
        0xA1A92C70, 0x6027F3B0, 0xF9C595B1, 0x384B4A71, 0x11705FF2, 0xD0FE8032,
        0x491CE633, 0x889239F3, 0x1B6ACD35, 0xDAE412F5, 0x430674F4, 0x8288AB34,
        0xABB3BEB7, 0x6A3D6177, 0xF3DF0776, 0x3251D8B6, 0x0F5FE8BB, 0xCED1377B,
        0x5733517A, 0x96BD8EBA, 0xBF869B39, 0x7E0844F9, 0xE7EA22F8, 0x2664FD38,
        0xB59C09FE, 0x7412D63E, 0xEDF0B03F, 0x2C7E6FFF, 0x05457A7C, 0xC4CBA5BC,
        0x5D29C3BD, 0x9CA71C7D, 0x2735A3A7, 0xE6BB7C67, 0x7F591A66, 0xBED7C5A6,
        0x97ECD025, 0x56620FE5, 0xCF8069E4, 0x0E0EB624, 0x9DF642E2, 0x5C789D22,
        0xC59AFB23, 0x041424E3, 0x2D2F3160, 0xECA1EEA0, 0x754388A1, 0xB4CD5761,
        0x89C3676C, 0x484DB8AC, 0xD1AFDEAD, 0x1021016D, 0x391A14EE, 0xF894CB2E,
        0x6176AD2F, 0xA0F872EF, 0x33008629, 0xF28E59E9, 0x6B6C3FE8, 0xAAE2E028,
        0x83D9F5AB, 0x42572A6B, 0xDBB54C6A, 0x1A3B93AA,
    },

    {
        0x00000000, 0x9BA54C6F, 0xEC3B9E9F, 0x779ED2F0, 0x03063B7F, 0x98A37710,
        0xEF3DA5E0, 0x7498E98F, 0x060C76FE, 0x9DA93A91, 0xEA37E861, 0x7192A40E,
        0x050A4D81, 0x9EAF01EE, 0xE931D31E, 0x72949F71, 0x0C18EDFC, 0x97BDA193,
        0xE0237363, 0x7B863F0C, 0x0F1ED683, 0x94BB9AEC, 0xE325481C, 0x78800473,
        0x0A149B02, 0x91B1D76D, 0xE62F059D, 0x7D8A49F2, 0x0912A07D, 0x92B7EC12,
        0xE5293EE2, 0x7E8C728D, 0x1831DBF8, 0x83949797, 0xF40A4567, 0x6FAF0908,
        0x1B37E087, 0x8092ACE8, 0xF70C7E18, 0x6CA93277, 0x1E3DAD06, 0x8598E169,
        0xF2063399, 0x69A37FF6, 0x1D3B9679, 0x869EDA16, 0xF10008E6, 0x6AA54489,
        0x14293604, 0x8F8C7A6B, 0xF812A89B, 0x63B7E4F4, 0x172F0D7B, 0x8C8A4114,
        0xFB1493E4, 0x60B1DF8B, 0x122540FA, 0x89800C95, 0xFE1EDE65, 0x65BB920A,
        0x11237B85, 0x8A8637EA, 0xFD18E51A, 0x66BDA975, 0x3063B7F0, 0xABC6FB9F,
        0xDC58296F, 0x47FD6500, 0x33658C8F, 0xA8C0C0E0, 0xDF5E1210, 0x44FB5E7F,
        0x366FC10E, 0xADCA8D61, 0xDA545F91, 0x41F113FE, 0x3569FA71, 0xAECCB61E,
        0xD95264EE, 0x42F72881, 0x3C7B5A0C, 0xA7DE1663, 0xD040C493, 0x4BE588FC,
        0x3F7D6173, 0xA4D82D1C, 0xD346FFEC, 0x48E3B383, 0x3A772CF2, 0xA1D2609D,
        0xD64CB26D, 0x4DE9FE02, 0x3971178D, 0xA2D45BE2, 0xD54A8912, 0x4EEFC57D,
        0x28526C08, 0xB3F72067, 0xC469F297, 0x5FCCBEF8, 0x2B545777, 0xB0F11B18,
        0xC76FC9E8, 0x5CCA8587, 0x2E5E1AF6, 0xB5FB5699, 0xC2658469, 0x59C0C806,
        0x2D582189, 0xB6FD6DE6, 0xC163BF16, 0x5AC6F379, 0x244A81F4, 0xBFEFCD9B,
        0xC8711F6B, 0x53D45304, 0x274CBA8B, 0xBCE9F6E4, 0xCB772414, 0x50D2687B,
        0x2246F70A, 0xB9E3BB65, 0xCE7D6995, 0x55D825FA, 0x2140CC75, 0xBAE5801A,
        0xCD7B52EA, 0x56DE1E85, 0x60C76FE0, 0xFB62238F, 0x8CFCF17F, 0x1759BD10,
        0x63C1549F, 0xF86418F0, 0x8FFACA00, 0x145F866F, 0x66CB191E, 0xFD6E5571,
        0x8AF08781, 0x1155CBEE, 0x65CD2261, 0xFE686E0E, 0x89F6BCFE, 0x1253F091,
        0x6CDF821C, 0xF77ACE73, 0x80E41C83, 0x1B4150EC, 0x6FD9B963, 0xF47CF50C,
        0x83E227FC, 0x18476B93, 0x6AD3F4E2, 0xF176B88D, 0x86E86A7D, 0x1D4D2612,
        0x69D5CF9D, 0xF27083F2, 0x85EE5102, 0x1E4B1D6D, 0x78F6B418, 0xE353F877,
        0x94CD2A87, 0x0F6866E8, 0x7BF08F67, 0xE055C308, 0x97CB11F8, 0x0C6E5D97,
        0x7EFAC2E6, 0xE55F8E89, 0x92C15C79, 0x09641016, 0x7DFCF999, 0xE659B5F6,
        0x91C76706, 0x0A622B69, 0x74EE59E4, 0xEF4B158B, 0x98D5C77B, 0x03708B14,
        0x77E8629B, 0xEC4D2EF4, 0x9BD3FC04, 0x0076B06B, 0x72E22F1A, 0xE9476375,
        0x9ED9B185, 0x057CFDEA, 0x71E41465, 0xEA41580A, 0x9DDF8AFA, 0x067AC695,
        0x50A4D810, 0xCB01947F, 0xBC9F468F, 0x273A0AE0, 0x53A2E36F, 0xC807AF00,
        0xBF997DF0, 0x243C319F, 0x56A8AEEE, 0xCD0DE281, 0xBA933071, 0x21367C1E,
        0x55AE9591, 0xCE0BD9FE, 0xB9950B0E, 0x22304761, 0x5CBC35EC, 0xC7197983,
        0xB087AB73, 0x2B22E71C, 0x5FBA0E93, 0xC41F42FC, 0xB381900C, 0x2824DC63,
        0x5AB04312, 0xC1150F7D, 0xB68BDD8D, 0x2D2E91E2, 0x59B6786D, 0xC2133402,
        0xB58DE6F2, 0x2E28AA9D, 0x489503E8, 0xD3304F87, 0xA4AE9D77, 0x3F0BD118,
        0x4B933897, 0xD03674F8, 0xA7A8A608, 0x3C0DEA67, 0x4E997516, 0xD53C3979,
        0xA2A2EB89, 0x3907A7E6, 0x4D9F4E69, 0xD63A0206, 0xA1A4D0F6, 0x3A019C99,
        0x448DEE14, 0xDF28A27B, 0xA8B6708B, 0x33133CE4, 0x478BD56B, 0xDC2E9904,
        0xABB04BF4, 0x3015079B, 0x428198EA, 0xD924D485, 0xAEBA0675, 0x351F4A1A,
        0x4187A395, 0xDA22EFFA, 0xADBC3D0A, 0x36197165,
    },

    {
        0x00000000, 0xDD96D985, 0x605CB54B, 0xBDCA6CCE, 0xC0B96A96, 0x1D2FB313,
        0xA0E5DFDD, 0x7D730658, 0x5A03D36D, 0x87950AE8, 0x3A5F6626, 0xE7C9BFA3,
        0x9ABAB9FB, 0x472C607E, 0xFAE60CB0, 0x2770D535, 0xB407A6DA, 0x69917F5F,
        0xD45B1391, 0x09CDCA14, 0x74BECC4C, 0xA92815C9, 0x14E27907, 0xC974A082,
        0xEE0475B7, 0x3392AC32, 0x8E58C0FC, 0x53CE1979, 0x2EBD1F21, 0xF32BC6A4,
        0x4EE1AA6A, 0x937773EF, 0xB37E4BF5, 0x6EE89270, 0xD322FEBE, 0x0EB4273B,
        0x73C72163, 0xAE51F8E6, 0x139B9428, 0xCE0D4DAD, 0xE97D9898, 0x34EB411D,
        0x89212DD3, 0x54B7F456, 0x29C4F20E, 0xF4522B8B, 0x49984745, 0x940E9EC0,
        0x0779ED2F, 0xDAEF34AA, 0x67255864, 0xBAB381E1, 0xC7C087B9, 0x1A565E3C,
        0xA79C32F2, 0x7A0AEB77, 0x5D7A3E42, 0x80ECE7C7, 0x3D268B09, 0xE0B0528C,
        0x9DC354D4, 0x40558D51, 0xFD9FE19F, 0x2009381A, 0xBD8D91AB, 0x601B482E,
        0xDDD124E0, 0x0047FD65, 0x7D34FB3D, 0xA0A222B8, 0x1D684E76, 0xC0FE97F3,
        0xE78E42C6, 0x3A189B43, 0x87D2F78D, 0x5A442E08, 0x27372850, 0xFAA1F1D5,
        0x476B9D1B, 0x9AFD449E, 0x098A3771, 0xD41CEEF4, 0x69D6823A, 0xB4405BBF,
        0xC9335DE7, 0x14A58462, 0xA96FE8AC, 0x74F93129, 0x5389E41C, 0x8E1F3D99,
        0x33D55157, 0xEE4388D2, 0x93308E8A, 0x4EA6570F, 0xF36C3BC1, 0x2EFAE244,
        0x0EF3DA5E, 0xD36503DB, 0x6EAF6F15, 0xB339B690, 0xCE4AB0C8, 0x13DC694D,
        0xAE160583, 0x7380DC06, 0x54F00933, 0x8966D0B6, 0x34ACBC78, 0xE93A65FD,
        0x944963A5, 0x49DFBA20, 0xF415D6EE, 0x29830F6B, 0xBAF47C84, 0x6762A501,
        0xDAA8C9CF, 0x073E104A, 0x7A4D1612, 0xA7DBCF97, 0x1A11A359, 0xC7877ADC,
        0xE0F7AFE9, 0x3D61766C, 0x80AB1AA2, 0x5D3DC327, 0x204EC57F, 0xFDD81CFA,
        0x40127034, 0x9D84A9B1, 0xA06A2517, 0x7DFCFC92, 0xC036905C, 0x1DA049D9,
        0x60D34F81, 0xBD459604, 0x008FFACA, 0xDD19234F, 0xFA69F67A, 0x27FF2FFF,
        0x9A354331, 0x47A39AB4, 0x3AD09CEC, 0xE7464569, 0x5A8C29A7, 0x871AF022,
        0x146D83CD, 0xC9FB5A48, 0x74313686, 0xA9A7EF03, 0xD4D4E95B, 0x094230DE,
        0xB4885C10, 0x691E8595, 0x4E6E50A0, 0x93F88925, 0x2E32E5EB, 0xF3A43C6E,
        0x8ED73A36, 0x5341E3B3, 0xEE8B8F7D, 0x331D56F8, 0x13146EE2, 0xCE82B767,
        0x7348DBA9, 0xAEDE022C, 0xD3AD0474, 0x0E3BDDF1, 0xB3F1B13F, 0x6E6768BA,
        0x4917BD8F, 0x9481640A, 0x294B08C4, 0xF4DDD141, 0x89AED719, 0x54380E9C,
        0xE9F26252, 0x3464BBD7, 0xA713C838, 0x7A8511BD, 0xC74F7D73, 0x1AD9A4F6,
        0x67AAA2AE, 0xBA3C7B2B, 0x07F617E5, 0xDA60CE60, 0xFD101B55, 0x2086C2D0,
        0x9D4CAE1E, 0x40DA779B, 0x3DA971C3, 0xE03FA846, 0x5DF5C488, 0x80631D0D,
        0x1DE7B4BC, 0xC0716D39, 0x7DBB01F7, 0xA02DD872, 0xDD5EDE2A, 0x00C807AF,
        0xBD026B61, 0x6094B2E4, 0x47E467D1, 0x9A72BE54, 0x27B8D29A, 0xFA2E0B1F,
        0x875D0D47, 0x5ACBD4C2, 0xE701B80C, 0x3A976189, 0xA9E01266, 0x7476CBE3,
        0xC9BCA72D, 0x142A7EA8, 0x695978F0, 0xB4CFA175, 0x0905CDBB, 0xD493143E,
        0xF3E3C10B, 0x2E75188E, 0x93BF7440, 0x4E29ADC5, 0x335AAB9D, 0xEECC7218,
        0x53061ED6, 0x8E90C753, 0xAE99FF49, 0x730F26CC, 0xCEC54A02, 0x13539387,
        0x6E2095DF, 0xB3B64C5A, 0x0E7C2094, 0xD3EAF911, 0xF49A2C24, 0x290CF5A1,
        0x94C6996F, 0x495040EA, 0x342346B2, 0xE9B59F37, 0x547FF3F9, 0x89E92A7C,
        0x1A9E5993, 0xC7088016, 0x7AC2ECD8, 0xA754355D, 0xDA273305, 0x07B1EA80,
        0xBA7B864E, 0x67ED5FCB, 0x409D8AFE, 0x9D0B537B, 0x20C13FB5, 0xFD57E630,
        0x8024E068, 0x5DB239ED, 0xE0785523, 0x3DEE8CA6,
    },

    {
        0x00000000, 0x9D0FE176, 0xE16EC4AD, 0x7C6125DB, 0x19AC8F1B, 0x84A36E6D,
        0xF8C24BB6, 0x65CDAAC0, 0x33591E36, 0xAE56FF40, 0xD237DA9B, 0x4F383BED,
        0x2AF5912D, 0xB7FA705B, 0xCB9B5580, 0x5694B4F6, 0x66B23C6C, 0xFBBDDD1A,
        0x87DCF8C1, 0x1AD319B7, 0x7F1EB377, 0xE2115201, 0x9E7077DA, 0x037F96AC,
        0x55EB225A, 0xC8E4C32C, 0xB485E6F7, 0x298A0781, 0x4C47AD41, 0xD1484C37,
        0xAD2969EC, 0x3026889A, 0xCD6478D8, 0x506B99AE, 0x2C0ABC75, 0xB1055D03,
        0xD4C8F7C3, 0x49C716B5, 0x35A6336E, 0xA8A9D218, 0xFE3D66EE, 0x63328798,
        0x1F53A243, 0x825C4335, 0xE791E9F5, 0x7A9E0883, 0x06FF2D58, 0x9BF0CC2E,
        0xABD644B4, 0x36D9A5C2, 0x4AB88019, 0xD7B7616F, 0xB27ACBAF, 0x2F752AD9,
        0x53140F02, 0xCE1BEE74, 0x988F5A82, 0x0580BBF4, 0x79E19E2F, 0xE4EE7F59,
        0x8123D599, 0x1C2C34EF, 0x604D1134, 0xFD42F042, 0x41B9F7F1, 0xDCB61687,
        0xA0D7335C, 0x3DD8D22A, 0x581578EA, 0xC51A999C, 0xB97BBC47, 0x24745D31,
        0x72E0E9C7, 0xEFEF08B1, 0x938E2D6A, 0x0E81CC1C, 0x6B4C66DC, 0xF64387AA,
        0x8A22A271, 0x172D4307, 0x270BCB9D, 0xBA042AEB, 0xC6650F30, 0x5B6AEE46,
        0x3EA74486, 0xA3A8A5F0, 0xDFC9802B, 0x42C6615D, 0x1452D5AB, 0x895D34DD,
        0xF53C1106, 0x6833F070, 0x0DFE5AB0, 0x90F1BBC6, 0xEC909E1D, 0x719F7F6B,
        0x8CDD8F29, 0x11D26E5F, 0x6DB34B84, 0xF0BCAAF2, 0x95710032, 0x087EE144,
        0x741FC49F, 0xE91025E9, 0xBF84911F, 0x228B7069, 0x5EEA55B2, 0xC3E5B4C4,
        0xA6281E04, 0x3B27FF72, 0x4746DAA9, 0xDA493BDF, 0xEA6FB345, 0x77605233,
        0x0B0177E8, 0x960E969E, 0xF3C33C5E, 0x6ECCDD28, 0x12ADF8F3, 0x8FA21985,
        0xD936AD73, 0x44394C05, 0x385869DE, 0xA55788A8, 0xC09A2268, 0x5D95C31E,
        0x21F4E6C5, 0xBCFB07B3, 0x8373EFE2, 0x1E7C0E94, 0x621D2B4F, 0xFF12CA39,
        0x9ADF60F9, 0x07D0818F, 0x7BB1A454, 0xE6BE4522, 0xB02AF1D4, 0x2D2510A2,
        0x51443579, 0xCC4BD40F, 0xA9867ECF, 0x34899FB9, 0x48E8BA62, 0xD5E75B14,
        0xE5C1D38E, 0x78CE32F8, 0x04AF1723, 0x99A0F655, 0xFC6D5C95, 0x6162BDE3,
        0x1D039838, 0x800C794E, 0xD698CDB8, 0x4B972CCE, 0x37F60915, 0xAAF9E863,
        0xCF3442A3, 0x523BA3D5, 0x2E5A860E, 0xB3556778, 0x4E17973A, 0xD318764C,
        0xAF795397, 0x3276B2E1, 0x57BB1821, 0xCAB4F957, 0xB6D5DC8C, 0x2BDA3DFA,
        0x7D4E890C, 0xE041687A, 0x9C204DA1, 0x012FACD7, 0x64E20617, 0xF9EDE761,
        0x858CC2BA, 0x188323CC, 0x28A5AB56, 0xB5AA4A20, 0xC9CB6FFB, 0x54C48E8D,
        0x3109244D, 0xAC06C53B, 0xD067E0E0, 0x4D680196, 0x1BFCB560, 0x86F35416,
        0xFA9271CD, 0x679D90BB, 0x02503A7B, 0x9F5FDB0D, 0xE33EFED6, 0x7E311FA0,
        0xC2CA1813, 0x5FC5F965, 0x23A4DCBE, 0xBEAB3DC8, 0xDB669708, 0x4669767E,
        0x3A0853A5, 0xA707B2D3, 0xF1930625, 0x6C9CE753, 0x10FDC288, 0x8DF223FE,
        0xE83F893E, 0x75306848, 0x09514D93, 0x945EACE5, 0xA478247F, 0x3977C509,
        0x4516E0D2, 0xD81901A4, 0xBDD4AB64, 0x20DB4A12, 0x5CBA6FC9, 0xC1B58EBF,
        0x97213A49, 0x0A2EDB3F, 0x764FFEE4, 0xEB401F92, 0x8E8DB552, 0x13825424,
        0x6FE371FF, 0xF2EC9089, 0x0FAE60CB, 0x92A181BD, 0xEEC0A466, 0x73CF4510,
        0x1602EFD0, 0x8B0D0EA6, 0xF76C2B7D, 0x6A63CA0B, 0x3CF77EFD, 0xA1F89F8B,
        0xDD99BA50, 0x40965B26, 0x255BF1E6, 0xB8541090, 0xC435354B, 0x593AD43D,
        0x691C5CA7, 0xF413BDD1, 0x8872980A, 0x157D797C, 0x70B0D3BC, 0xEDBF32CA,
        0x91DE1711, 0x0CD1F667, 0x5A454291, 0xC74AA3E7, 0xBB2B863C, 0x2624674A,
        0x43E9CD8A, 0xDEE62CFC, 0xA2870927, 0x3F88E851,
    },

    {
        0x00000000, 0xB9FBDBE8, 0xA886B191, 0x117D6A79, 0x8A7C6563, 0x3387BE8B,
        0x22FAD4F2, 0x9B010F1A, 0xCF89CC87, 0x7672176F, 0x670F7D16, 0xDEF4A6FE,
        0x45F5A9E4, 0xFC0E720C, 0xED731875, 0x5488C39D, 0x44629F4F, 0xFD9944A7,
        0xECE42EDE, 0x551FF536, 0xCE1EFA2C, 0x77E521C4, 0x66984BBD, 0xDF639055,
        0x8BEB53C8, 0x32108820, 0x236DE259, 0x9A9639B1, 0x019736AB, 0xB86CED43,
        0xA911873A, 0x10EA5CD2, 0x88C53E9E, 0x313EE576, 0x20438F0F, 0x99B854E7,
        0x02B95BFD, 0xBB428015, 0xAA3FEA6C, 0x13C43184, 0x474CF219, 0xFEB729F1,
        0xEFCA4388, 0x56319860, 0xCD30977A, 0x74CB4C92, 0x65B626EB, 0xDC4DFD03,
        0xCCA7A1D1, 0x755C7A39, 0x64211040, 0xDDDACBA8, 0x46DBC4B2, 0xFF201F5A,
        0xEE5D7523, 0x57A6AECB, 0x032E6D56, 0xBAD5B6BE, 0xABA8DCC7, 0x1253072F,
        0x89520835, 0x30A9D3DD, 0x21D4B9A4, 0x982F624C, 0xCAFB7B7D, 0x7300A095,
        0x627DCAEC, 0xDB861104, 0x40871E1E, 0xF97CC5F6, 0xE801AF8F, 0x51FA7467,
        0x0572B7FA, 0xBC896C12, 0xADF4066B, 0x140FDD83, 0x8F0ED299, 0x36F50971,
        0x27886308, 0x9E73B8E0, 0x8E99E432, 0x37623FDA, 0x261F55A3, 0x9FE48E4B,
        0x04E58151, 0xBD1E5AB9, 0xAC6330C0, 0x1598EB28, 0x411028B5, 0xF8EBF35D,
        0xE9969924, 0x506D42CC, 0xCB6C4DD6, 0x7297963E, 0x63EAFC47, 0xDA1127AF,
        0x423E45E3, 0xFBC59E0B, 0xEAB8F472, 0x53432F9A, 0xC8422080, 0x71B9FB68,
        0x60C49111, 0xD93F4AF9, 0x8DB78964, 0x344C528C, 0x253138F5, 0x9CCAE31D,
        0x07CBEC07, 0xBE3037EF, 0xAF4D5D96, 0x16B6867E, 0x065CDAAC, 0xBFA70144,
        0xAEDA6B3D, 0x1721B0D5, 0x8C20BFCF, 0x35DB6427, 0x24A60E5E, 0x9D5DD5B6,
        0xC9D5162B, 0x702ECDC3, 0x6153A7BA, 0xD8A87C52, 0x43A97348, 0xFA52A8A0,
        0xEB2FC2D9, 0x52D41931, 0x4E87F0BB, 0xF77C2B53, 0xE601412A, 0x5FFA9AC2,
        0xC4FB95D8, 0x7D004E30, 0x6C7D2449, 0xD586FFA1, 0x810E3C3C, 0x38F5E7D4,
        0x29888DAD, 0x90735645, 0x0B72595F, 0xB28982B7, 0xA3F4E8CE, 0x1A0F3326,
        0x0AE56FF4, 0xB31EB41C, 0xA263DE65, 0x1B98058D, 0x80990A97, 0x3962D17F,
        0x281FBB06, 0x91E460EE, 0xC56CA373, 0x7C97789B, 0x6DEA12E2, 0xD411C90A,
        0x4F10C610, 0xF6EB1DF8, 0xE7967781, 0x5E6DAC69, 0xC642CE25, 0x7FB915CD,
        0x6EC47FB4, 0xD73FA45C, 0x4C3EAB46, 0xF5C570AE, 0xE4B81AD7, 0x5D43C13F,
        0x09CB02A2, 0xB030D94A, 0xA14DB333, 0x18B668DB, 0x83B767C1, 0x3A4CBC29,
        0x2B31D650, 0x92CA0DB8, 0x8220516A, 0x3BDB8A82, 0x2AA6E0FB, 0x935D3B13,
        0x085C3409, 0xB1A7EFE1, 0xA0DA8598, 0x19215E70, 0x4DA99DED, 0xF4524605,
        0xE52F2C7C, 0x5CD4F794, 0xC7D5F88E, 0x7E2E2366, 0x6F53491F, 0xD6A892F7,
        0x847C8BC6, 0x3D87502E, 0x2CFA3A57, 0x9501E1BF, 0x0E00EEA5, 0xB7FB354D,
        0xA6865F34, 0x1F7D84DC, 0x4BF54741, 0xF20E9CA9, 0xE373F6D0, 0x5A882D38,
        0xC1892222, 0x7872F9CA, 0x690F93B3, 0xD0F4485B, 0xC01E1489, 0x79E5CF61,
        0x6898A518, 0xD1637EF0, 0x4A6271EA, 0xF399AA02, 0xE2E4C07B, 0x5B1F1B93,
        0x0F97D80E, 0xB66C03E6, 0xA711699F, 0x1EEAB277, 0x85EBBD6D, 0x3C106685,
        0x2D6D0CFC, 0x9496D714, 0x0CB9B558, 0xB5426EB0, 0xA43F04C9, 0x1DC4DF21,
        0x86C5D03B, 0x3F3E0BD3, 0x2E4361AA, 0x97B8BA42, 0xC33079DF, 0x7ACBA237,
        0x6BB6C84E, 0xD24D13A6, 0x494C1CBC, 0xF0B7C754, 0xE1CAAD2D, 0x583176C5,
        0x48DB2A17, 0xF120F1FF, 0xE05D9B86, 0x59A6406E, 0xC2A74F74, 0x7B5C949C,
        0x6A21FEE5, 0xD3DA250D, 0x8752E690, 0x3EA93D78, 0x2FD45701, 0x962F8CE9,
        0x0D2E83F3, 0xB4D5581B, 0xA5A83262, 0x1C53E98A,
    },

    {
        0x00000000, 0xAE689191, 0x87A02563, 0x29C8B4F2, 0xD4314C87, 0x7A59DD16,
        0x539169E4, 0xFDF9F875, 0x73139F4F, 0xDD7B0EDE, 0xF4B3BA2C, 0x5ADB2BBD,
        0xA722D3C8, 0x094A4259, 0x2082F6AB, 0x8EEA673A, 0xE6273E9E, 0x484FAF0F,
        0x61871BFD, 0xCFEF8A6C, 0x32167219, 0x9C7EE388, 0xB5B6577A, 0x1BDEC6EB,
        0x9534A1D1, 0x3B5C3040, 0x129484B2, 0xBCFC1523, 0x4105ED56, 0xEF6D7CC7,
        0xC6A5C835, 0x68CD59A4, 0x173F7B7D, 0xB957EAEC, 0x909F5E1E, 0x3EF7CF8F,
        0xC30E37FA, 0x6D66A66B, 0x44AE1299, 0xEAC68308, 0x642CE432, 0xCA4475A3,
        0xE38CC151, 0x4DE450C0, 0xB01DA8B5, 0x1E753924, 0x37BD8DD6, 0x99D51C47,
        0xF11845E3, 0x5F70D472, 0x76B86080, 0xD8D0F111, 0x25290964, 0x8B4198F5,
        0xA2892C07, 0x0CE1BD96, 0x820BDAAC, 0x2C634B3D, 0x05ABFFCF, 0xABC36E5E,
        0x563A962B, 0xF85207BA, 0xD19AB348, 0x7FF222D9, 0x2E7EF6FA, 0x8016676B,
        0xA9DED399, 0x07B64208, 0xFA4FBA7D, 0x54272BEC, 0x7DEF9F1E, 0xD3870E8F,
        0x5D6D69B5, 0xF305F824, 0xDACD4CD6, 0x74A5DD47, 0x895C2532, 0x2734B4A3,
        0x0EFC0051, 0xA09491C0, 0xC859C864, 0x663159F5, 0x4FF9ED07, 0xE1917C96,
        0x1C6884E3, 0xB2001572, 0x9BC8A180, 0x35A03011, 0xBB4A572B, 0x1522C6BA,
        0x3CEA7248, 0x9282E3D9, 0x6F7B1BAC, 0xC1138A3D, 0xE8DB3ECF, 0x46B3AF5E,
        0x39418D87, 0x97291C16, 0xBEE1A8E4, 0x10893975, 0xED70C100, 0x43185091,
        0x6AD0E463, 0xC4B875F2, 0x4A5212C8, 0xE43A8359, 0xCDF237AB, 0x639AA63A,
        0x9E635E4F, 0x300BCFDE, 0x19C37B2C, 0xB7ABEABD, 0xDF66B319, 0x710E2288,
        0x58C6967A, 0xF6AE07EB, 0x0B57FF9E, 0xA53F6E0F, 0x8CF7DAFD, 0x229F4B6C,
        0xAC752C56, 0x021DBDC7, 0x2BD50935, 0x85BD98A4, 0x784460D1, 0xD62CF140,
        0xFFE445B2, 0x518CD423, 0x5CFDEDF4, 0xF2957C65, 0xDB5DC897, 0x75355906,
        0x88CCA173, 0x26A430E2, 0x0F6C8410, 0xA1041581, 0x2FEE72BB, 0x8186E32A,
        0xA84E57D8, 0x0626C649, 0xFBDF3E3C, 0x55B7AFAD, 0x7C7F1B5F, 0xD2178ACE,
        0xBADAD36A, 0x14B242FB, 0x3D7AF609, 0x93126798, 0x6EEB9FED, 0xC0830E7C,
        0xE94BBA8E, 0x47232B1F, 0xC9C94C25, 0x67A1DDB4, 0x4E696946, 0xE001F8D7,
        0x1DF800A2, 0xB3909133, 0x9A5825C1, 0x3430B450, 0x4BC29689, 0xE5AA0718,
        0xCC62B3EA, 0x620A227B, 0x9FF3DA0E, 0x319B4B9F, 0x1853FF6D, 0xB63B6EFC,
        0x38D109C6, 0x96B99857, 0xBF712CA5, 0x1119BD34, 0xECE04541, 0x4288D4D0,
        0x6B406022, 0xC528F1B3, 0xADE5A817, 0x038D3986, 0x2A458D74, 0x842D1CE5,
        0x79D4E490, 0xD7BC7501, 0xFE74C1F3, 0x501C5062, 0xDEF63758, 0x709EA6C9,
        0x5956123B, 0xF73E83AA, 0x0AC77BDF, 0xA4AFEA4E, 0x8D675EBC, 0x230FCF2D,
        0x72831B0E, 0xDCEB8A9F, 0xF5233E6D, 0x5B4BAFFC, 0xA6B25789, 0x08DAC618,
        0x211272EA, 0x8F7AE37B, 0x01908441, 0xAFF815D0, 0x8630A122, 0x285830B3,
        0xD5A1C8C6, 0x7BC95957, 0x5201EDA5, 0xFC697C34, 0x94A42590, 0x3ACCB401,
        0x130400F3, 0xBD6C9162, 0x40956917, 0xEEFDF886, 0xC7354C74, 0x695DDDE5,
        0xE7B7BADF, 0x49DF2B4E, 0x60179FBC, 0xCE7F0E2D, 0x3386F658, 0x9DEE67C9,
        0xB426D33B, 0x1A4E42AA, 0x65BC6073, 0xCBD4F1E2, 0xE21C4510, 0x4C74D481,
        0xB18D2CF4, 0x1FE5BD65, 0x362D0997, 0x98459806, 0x16AFFF3C, 0xB8C76EAD,
        0x910FDA5F, 0x3F674BCE, 0xC29EB3BB, 0x6CF6222A, 0x453E96D8, 0xEB560749,
        0x839B5EED, 0x2DF3CF7C, 0x043B7B8E, 0xAA53EA1F, 0x57AA126A, 0xF9C283FB,
        0xD00A3709, 0x7E62A698, 0xF088C1A2, 0x5EE05033, 0x7728E4C1, 0xD9407550,
        0x24B98D25, 0x8AD11CB4, 0xA319A846, 0x0D7139D7,
    }
#endif // CRC32_USE_LOOKUP_TABLE_SLICING_BY_16
};
#endif // NO_LUT



#endif
