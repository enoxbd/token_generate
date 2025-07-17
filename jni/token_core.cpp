// token_core.cpp
#include "token_core.hpp"
#include "utils.hpp"
#include "sha256_small.hpp"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <android/log.h>

#define AES_KEY "enoxbdmontasir12"

std::string encryptAES(const std::string& data, const std::string& key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char out[1024];
    int out_len1 = 0, out_len2 = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, (unsigned char*)key.c_str(), NULL);
    EVP_EncryptUpdate(ctx, out, &out_len1, (unsigned char*)data.c_str(), data.length());
    EVP_EncryptFinal_ex(ctx, out + out_len1, &out_len2);

    EVP_CIPHER_CTX_free(ctx);
    std::string result(reinterpret_cast<char*>(out), out_len1 + out_len2);
    return result;
}

std::string generateSecureToken(const std::string& session_id, const std::string& device_id) {
    time_t now = time(nullptr);
    std::string timestamp = std::to_string(now);
    std::string random_key = generateRandomKey(12);
    std::string data = session_id + ":" + device_id + ":" + timestamp + ":" + random_key;

    std::string hashed = sha256(data);
    std::string encrypted = encryptAES(hashed, AES_KEY);
    return encrypted;
}
