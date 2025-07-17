#ifndef AES_HPP
#define AES_HPP

#include <string>

// AES 128-bit CBC মোড এনক্রিপশন
std::string aesEncrypt(const std::string& plainText, const std::string& password);

// AES 128-bit CBC মোড ডিক্রিপশন (প্রয়োজনে)
std::string aesDecrypt(const std::string& cipherText, const std::string& password);

#endif
