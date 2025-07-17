#include "aes.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string>
#include <vector>
#include <stdexcept>
#include <android/log.h>

#define LOG_TAG "AES"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// Helper: convert std::string to std::vector<unsigned char>
static std::vector<unsigned char> stringToBytes(const std::string& str) {
    return std::vector<unsigned char>(str.begin(), str.end());
}

// Helper: convert std::vector<unsigned char> to std::string
static std::string bytesToString(const std::vector<unsigned char>& data) {
    return std::string(data.begin(), data.end());
}

// Derive key and IV from password using OpenSSL EVP_BytesToKey (MD5)
static bool deriveKeyAndIV(const std::string& password, std::vector<unsigned char>& key, std::vector<unsigned char>& iv) {
    key.resize(16);
    iv.resize(16);
    const unsigned char* salt = nullptr;
    int count = EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(),
                              salt,
                              (const unsigned char*)password.data(),
                              password.size(),
                              1,
                              key.data(),
                              iv.data());
    return count == 16;
}

std::string aesEncrypt(const std::string& plainText, const std::string& password) {
    std::vector<unsigned char> key, iv;
    if (!deriveKeyAndIV(password, key, iv)) {
        LOGI("Key derivation failed");
        throw std::runtime_error("Key derivation failed");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    std::vector<unsigned char> cipherText(plainText.size() + EVP_CIPHER_block_size(EVP_aes_128_cbc()));
    int len = 0;
    int cipherLen = 0;

    if (1 != EVP_EncryptUpdate(ctx, cipherText.data(), &len, (const unsigned char*)plainText.data(), plainText.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    cipherLen = len;

    if (1 != EVP_EncryptFinal_ex(ctx, cipherText.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    cipherLen += len;

    EVP_CIPHER_CTX_free(ctx);

    cipherText.resize(cipherLen);

    // Base64 encode if needed, else convert to hex or raw bytes - here returning raw bytes as string
    return bytesToString(cipherText);
}

std::string aesDecrypt(const std::string& cipherText, const std::string& password) {
    std::vector<unsigned char> key, iv;
    if (!deriveKeyAndIV(password, key, iv)) {
        LOGI("Key derivation failed");
        throw std::runtime_error("Key derivation failed");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }

    std::vector<unsigned char> plainText(cipherText.size());
    int len = 0;
    int plainLen = 0;

    if (1 != EVP_DecryptUpdate(ctx, plainText.data(), &len, (const unsigned char*)cipherText.data(), cipherText.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }
    plainLen = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plainText.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptFinal_ex failed");
    }
    plainLen += len;

    EVP_CIPHER_CTX_free(ctx);

    plainText.resize(plainLen);
    return bytesToString(plainText);
}
