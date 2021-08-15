/**
 * @file crypto.hpp
 * @author Bensuperpc (bensuperpc@gmail.com)
 * @brief
 * @version 1.0.0
 * @date 2021-04-01
 *
 * MIT License
 *
 */

/*
** Source:
https://stackoverflow.com/questions/178265/what-is-the-most-hard-to-understand-piece-of-c-code-you-know
https://cs.uwaterloo.ca/~m32rober/rsqrt.pdf
https://github.com/bavlayan/Encrypt-Decrypt-with-OpenSSL---RSA
*/

#ifndef CRYPTO_HPP_
#define CRYPTO_HPP_

#define BUFFSIZE 16384

#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

// For MD5 and SHA
#include <boost/crc.hpp> //CRC32
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <string_view>

//#include "openssl_rsa.h"

#define BUFFSIZE 16384

namespace my {
namespace crypto {
/**
 * @brief Get the md5hash object
 *
 * @param str
 * @return std::string
 */
std::string get_md5hash(const std::string &str);
// void get_md5hash_from_string(const unsigned char *, size_t &);
/**
 * @brief Get the md5hash from string object
 *
 * @param str
 * @return std::string
 */
std::string get_md5hash_from_string(const std::string &str);

/**
 * @brief Get the sha1hash object
 *
 * @param str
 * @return std::string
 */
std::string get_sha1hash(const std::string &str);
// void get_sha1hash_from_string(const unsigned char *, size_t &);

/**
 * @brief Get the sha1hash from string object
 *
 * @param str
 * @return std::string
 */
std::string get_sha1hash_from_string(const std::string &str);

/**
 * @brief Get the sha224hash object
 *
 * @param str
 * @return std::string
 */
std::string get_sha224hash(const std::string &str);
// void get_sha224hash_from_string(const unsigned char *, size_t &);

/**
 * @brief Get the sha224hash from string object
 *
 * @param str
 * @return std::string
 */
std::string get_sha224hash_from_string(const std::string &str);

/**
 * @brief Get the sha256hash object
 *
 * @param str
 * @return std::string
 */
std::string get_sha256hash(const std::string &str);
// void get_sha256hash_from_string(const unsigned char *, size_t &);

/**
 * @brief Get the sha256hash from string object
 *
 * @param str
 * @return std::string
 */
std::string get_sha256hash_from_string(const std::string &str);

/**
 * @brief Get the sha384hash object
 *
 * @param str
 * @return std::string
 */
std::string get_sha384hash(const std::string &str);
// void get_sha384hash_from_string(const unsigned char *, size_t &);

/**
 * @brief Get the sha384hash from string object
 *
 * @param str
 * @return std::string
 */
std::string get_sha384hash_from_string(const std::string &str);

/**
 * @brief Get the sha512hash object
 *
 * @param str
 * @return std::string
 */
std::string get_sha512hash(const std::string &str);
// void get_sha512hash_from_string(const unsigned char *, size_t &);
/**
 * @brief Get the sha512hash from string object
 *
 * @param str
 * @return std::string
 */
std::string get_sha512hash_from_string(const std::string &str);
} // namespace crypto
} // namespace my
// https://www.quora.com/How-can-I-get-the-MD5-or-SHA-hash-of-a-file-in-C








std::string my::crypto::get_md5hash(const std::string &fname) {

  char buffer[BUFFSIZE];
  unsigned char digest[MD5_DIGEST_LENGTH]; // == 16

  std::stringstream ss;
  std::string md5string;

  std::ifstream ifs(fname, std::ifstream::binary);

  MD5_CTX md5Context;

  MD5_Init(&md5Context);

  while (ifs.good()) {
    ifs.read(buffer, BUFFSIZE);
    MD5_Update(&md5Context, buffer, static_cast<size_t>(ifs.gcount()));
  }

  ifs.close();

  auto &&res = MD5_Final(digest, &md5Context);

  if (res == 0) // hash failed
    return {};  // or raise an exception

  // ss << std::hex << std::uppercase << std::setfill('0');
  ss << std::hex << std::setfill('0');
  for (unsigned char uc : digest)
    ss << std::setw(2) << (int)uc;

  md5string = ss.str();

  return md5string;
}

std::string my::crypto::get_md5hash_from_string(const std::string &str) {
  unsigned char result[MD5_DIGEST_LENGTH];
  MD5((const unsigned char *)str.c_str(), str.size(), result);

  std::ostringstream sout;
  sout << std::hex << std::setfill('0');
  for (long long c : result) {
    sout << std::setw(2) << (long long)c;
  }
  return sout.str();
}

std::string my::crypto::get_sha1hash(const std::string &fname) {

  char buffer[BUFFSIZE];
  unsigned char digest[SHA_DIGEST_LENGTH];

  std::stringstream ss;
  std::string sha1string;

  std::ifstream ifs(fname, std::ifstream::binary);

  SHA_CTX sha1Context;

  SHA1_Init(&sha1Context);

  while (ifs.good()) {
    ifs.read(buffer, BUFFSIZE);
    SHA1_Update(&sha1Context, buffer, static_cast<size_t>(ifs.gcount()));
  }

  ifs.close();

  auto &&res = SHA1_Final(digest, &sha1Context);

  if (res == 0) // hash failed
    return {};  // or raise an exception

  // ss << std::hex << std::uppercase << std::setfill('0');
  ss << std::hex << std::setfill('0');
  for (unsigned char uc : digest)
    ss << std::setw(2) << (int)uc;

  sha1string = ss.str();

  return sha1string;
}

std::string my::crypto::get_sha1hash_from_string(const std::string &str) {
  unsigned char result[SHA_DIGEST_LENGTH];
  SHA1((const unsigned char *)str.c_str(), str.size(), result);

  std::ostringstream sout;
  sout << std::hex << std::setfill('0');
  for (long long c : result) {
    sout << std::setw(2) << (long long)c;
  }
  return sout.str();
}

std::string my::crypto::get_sha224hash(const std::string &fname) {

  char buffer[BUFFSIZE];
  unsigned char digest[SHA224_DIGEST_LENGTH];

  std::stringstream ss;
  std::string sha224string;

  std::ifstream ifs(fname, std::ifstream::binary);

  SHA256_CTX sha224Context;

  SHA224_Init(&sha224Context);

  while (ifs.good()) {
    ifs.read(buffer, BUFFSIZE);
    SHA256_Update(&sha224Context, buffer, static_cast<size_t>(ifs.gcount()));
  }

  ifs.close();

  auto &&res = SHA256_Final(digest, &sha224Context);

  if (res == 0) // hash failed
    return {};  // or raise an exception

  // ss << std::hex << std::uppercase << std::setfill('0');
  ss << std::hex << std::setfill('0');
  for (unsigned char uc : digest)
    ss << std::setw(2) << (int)uc;

  sha224string = ss.str();

  return sha224string;
}

std::string my::crypto::get_sha224hash_from_string(const std::string &str) {
  unsigned char result[SHA224_DIGEST_LENGTH];
  SHA224((const unsigned char *)str.c_str(), str.size(), result);

  std::ostringstream sout;
  sout << std::hex << std::setfill('0');
  for (long long c : result) {
    sout << std::setw(2) << (long long)c;
  }
  return sout.str();
}

std::string my::crypto::get_sha256hash(const std::string &fname) {

  char buffer[BUFFSIZE];
  unsigned char digest[SHA256_DIGEST_LENGTH];

  std::stringstream ss;
  std::string sha256string;

  std::ifstream ifs(fname, std::ifstream::binary);

  SHA256_CTX sha256Context;

  SHA256_Init(&sha256Context);

  while (ifs.good()) {
    ifs.read(buffer, BUFFSIZE);
    SHA256_Update(&sha256Context, buffer, static_cast<size_t>(ifs.gcount()));
  }

  ifs.close();

  auto &&res = SHA256_Final(digest, &sha256Context);

  if (res == 0) // hash failed
    return {};  // or raise an exception

  // ss << std::hex << std::uppercase << std::setfill('0');
  ss << std::hex << std::setfill('0');
  for (unsigned char uc : digest)
    ss << std::setw(2) << (int)uc;

  sha256string = ss.str();

  return sha256string;
}

std::string my::crypto::get_sha256hash_from_string(const std::string &str) {
  unsigned char result[SHA256_DIGEST_LENGTH];
  SHA256((const unsigned char *)str.c_str(), str.size(), result);

  std::ostringstream sout;
  sout << std::hex << std::setfill('0');
  for (long long c : result) {
    sout << std::setw(2) << (long long)c;
  }
  return sout.str();
}

std::string my::crypto::get_sha384hash(const std::string &fname) {

  char buffer[BUFFSIZE];
  unsigned char digest[SHA384_DIGEST_LENGTH];

  std::stringstream ss;
  std::string sha384string;

  std::ifstream ifs(fname, std::ifstream::binary);

  SHA512_CTX sha384Context;

  SHA384_Init(&sha384Context);

  while (ifs.good()) {
    ifs.read(buffer, BUFFSIZE);
    SHA384_Update(&sha384Context, buffer, static_cast<size_t>(ifs.gcount()));
  }

  ifs.close();

  auto &&res = SHA384_Final(digest, &sha384Context);

  if (res == 0) // hash failed
    return {};  // or raise an exception

  // ss << std::hex << std::uppercase << std::setfill('0');
  ss << std::hex << std::setfill('0');
  for (unsigned char uc : digest)
    ss << std::setw(2) << (int)uc;

  sha384string = ss.str();

  return sha384string;
}

std::string my::crypto::get_sha384hash_from_string(const std::string &str) {
  unsigned char result[SHA384_DIGEST_LENGTH];
  SHA384((const unsigned char *)str.c_str(), str.size(), result);

  std::ostringstream sout;
  sout << std::hex << std::setfill('0');
  for (long long c : result) {
    sout << std::setw(2) << (long long)c;
  }
  return sout.str();
}

std::string my::crypto::get_sha512hash(const std::string &fname) {

  char buffer[BUFFSIZE];
  unsigned char digest[SHA512_DIGEST_LENGTH];

  std::stringstream ss;
  std::string sha512string;

  std::ifstream ifs(fname, std::ifstream::binary);

  SHA512_CTX sha512Context;

  SHA512_Init(&sha512Context);

  while (ifs.good()) {
    ifs.read(buffer, BUFFSIZE);
    SHA512_Update(&sha512Context, buffer, static_cast<size_t>(ifs.gcount()));
  }

  ifs.close();

  auto &&res = SHA512_Final(digest, &sha512Context);

  if (res == 0) // hash failed
    return {};  // or raise an exception

  // ss << std::hex << std::uppercase << std::setfill('0');
  ss << std::hex << std::setfill('0');
  for (unsigned char uc : digest)
    ss << std::setw(2) << (int)uc;

  sha512string = ss.str();

  return sha512string;
}

std::string my::crypto::get_sha512hash_from_string(const std::string &str) {
  unsigned char result[SHA512_DIGEST_LENGTH];
  SHA512((const unsigned char *)str.c_str(), str.size(), result);

  std::ostringstream sout;
  sout << std::hex << std::setfill('0');
  for (long long c : result) {
    sout << std::setw(2) << (long long)c;
  }
  return sout.str();
}
/*
void my::crypto::get_sha512hash_from_string(const unsigned char *cstr, unsigned
char *out, size_t &size)
{
    unsigned char digest[SHA512_DIGEST_LENGTH];
    MD5Context context;
    MD5Init(&context);
    MD5Update(&context, string, strlen(string));
    MD5Final(digest, &context);

    unsigned char hash[SHA512_DIGEST_LENGTH]; // == 16
    SHA512(cstr, sizeof(*cstr) - 1, hash);
    unsigned char * hash_ptr = hash;
}
*/



#endif
