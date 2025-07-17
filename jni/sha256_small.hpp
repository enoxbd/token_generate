#ifndef SHA256_SMALL_HPP
#define SHA256_SMALL_HPP

#include <string>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>

std::string sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256_ctx;
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, input.c_str(), input.length());
    SHA256_Final(hash, &sha256_ctx);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return ss.str();
}

#endif // SHA256_SMALL_HPP
