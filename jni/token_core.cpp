// token_core.cpp
#include "token_core.hpp"
#include "utils.hpp"
#include "sha256_small.hpp"
#include "aes.hpp" // Lightweight AES

#define AES_KEY "enoxbdmontasir12"

std::string encryptAES(const std::string& data, const std::string& key) {
    AES aes;
    std::string padded = data;
    while (padded.length() % 16 != 0) padded += '\0'; // pad to block size
    std::string encrypted = aes.EncryptECB(padded, key);
    return encrypted;
}

std::string generateSecureToken(const std::string& session_id, const std::string& device_id) {
    time_t now = time(nullptr);
    std::string timestamp = std::to_string(now);
    std::string random_key = generateRandomKey(12);

    std::string raw = session_id + ":" + device_id + ":" + timestamp + ":" + random_key;
    std::string hashed = sha256(raw);
    std::string encrypted = encryptAES(hashed, AES_KEY);
    return encrypted;
}
