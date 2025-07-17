#include "TokenCore.hpp"
#include "JNIUtils.hpp"
#include <android/log.h>
#include <ctime>
#include <cstdlib>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h> // If openssl unavailable, implement your own sha256 or use BoringSSL in NDK
#include <openssl/aes.h>

#define LOG_TAG "TokenCore"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// AES key (must be 16 bytes for AES-128)
static const unsigned char AES_KEY[16] = "enoxbdmontasir12";

namespace tokencore {

// Helper SHA256 function
static std::string sha256(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)data.c_str(), data.length(), hash);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// Helper AES-128-CBC encrypt (no padding, so pad data yourself or implement padding)
static std::string aesEncrypt(const std::string& plaintext, const unsigned char* key) {
    AES_KEY aesKey;
    if (AES_set_encrypt_key(key, 128, &aesKey) < 0) {
        LOGE("AES_set_encrypt_key failed");
        return "";
    }

    // Use IV = 16 zero bytes for simplicity (you can randomize for stronger security)
    unsigned char iv[AES_BLOCK_SIZE] = {0};

    // Padding plaintext to multiple of 16 bytes
    int padding = AES_BLOCK_SIZE - (plaintext.size() % AES_BLOCK_SIZE);
    std::string padded = plaintext;
    padded.append(padding, (char)padding);

    std::string ciphertext;
    ciphertext.resize(padded.size());

    AES_cbc_encrypt((const unsigned char*)padded.data(), (unsigned char*)ciphertext.data(),
                    padded.size(), &aesKey, iv, AES_ENCRYPT);

    return ciphertext;
}

// Generate random string of given length (hex)
static std::string randomHexString(size_t length) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        result.push_back(hex_chars[rand() % 16]);
    }
    return result;
}

std::string generateSecureToken(JNIEnv* env, jobject context, const std::string& sessionKey) {
    // Get session_id (or user) from SharedPreferences named "User"
    std::string session_id = jniutils::getSharedPreferenceString(env, context, "User", sessionKey);
    if (session_id.empty()) {
        LOGE("Session ID is empty");
        return "";
    }

    // Get device info
    std::string fingerprint = jniutils::getBuildFingerprint(env);
    std::string androidId = jniutils::getAndroidID(env, context);
    std::string hwInfo = jniutils::getDeviceHardwareInfo(env);

    // Current timestamp
    std::time_t now = std::time(nullptr);

    // Random string
    std::string randomStr = randomHexString(16);

    // Compose raw token data
    std::stringstream tokenStream;
    tokenStream << session_id << "|"
                << fingerprint << "|"
                << androidId << "|"
                << hwInfo << "|"
                << now << "|"
                << randomStr;

    std::string rawToken = tokenStream.str();

    // Hash it
    std::string hashed = sha256(rawToken);

    // Encrypt with AES-128-CBC (key: enoxbdmontasir12)
    std::string encrypted = aesEncrypt(hashed, AES_KEY);

    // Return encrypted as base64 or hex (Sketchware can't decode base64 easily, hex is preferred)
    std::stringstream ss;
    for (unsigned char c : encrypted) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)c;
    }

    return ss.str();
}

} // namespace tokencore
