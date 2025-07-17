#ifndef SHA256_SMALL_H
#define SHA256_SMALL_H

#include <string>

void sha256(const unsigned char* data, size_t len, unsigned char* outHash);

std::string sha256_string(const std::string& input);

#endif
