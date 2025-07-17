#include "TokenCore.hpp"
#include "JNIUtils.hpp"
#include <android/log.h>
#include <ctime>
#include <cstdlib>
#include <sstream>
#include <iomanip>
#include "sha256_small.hpp"  // Your own SHA256 implementation

#define LOG_TAG "TokenCore"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Dummy AES 128-bit key (16 bytes, no null terminator)
static const unsigned char AES_KEY[16] = {
    'e','n','o','x','b','d','m','o','n','t','a','s','i','r','1','2'
};

namespace tokencore {

// Generate random hex string helper
static std::string randomHexString(size_t length) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        result.push_back(hex_chars[rand() % 16]);
    }
    return result;
}

// AES block size 16 bytes
constexpr int AES_BLOCK_SIZE = 16;

// PKCS7 padding
static std::string pkcs7Pad(const std::string& input) {
    int pad_len = AES_BLOCK_SIZE - (input.size() % AES_BLOCK_SIZE);
    std::string padded = input;
    padded.append(pad_len, (char)pad_len);
    return padded;
}

// Dummy AES-128-CBC encryption (XOR-based, for demo ONLY)
static std::string aesEncrypt(const std::string& plaintext, const unsigned char* key) {
    std::string padded = pkcs7Pad(plaintext);

    unsigned char iv[AES_BLOCK_SIZE] = {0};  // Zero IV for demo only

    std::string ciphertext(padded.size(), 0);

    for (size_t i = 0; i < padded.size(); i++) {
        ciphertext[i] = padded[i] ^ key[i % AES_BLOCK_SIZE] ^ iv[i % AES_BLOCK_SIZE];
    }

    return ciphertext;
}

// Main token generation function
std::string generateSecureToken(JNIEnv* env, jobject context, const std::string& sessionKey) {
    // Fetch session id string from SharedPreferences with name "shared" and key=sessionKey
    std::string session_id = jniutils::getSharedPreferenceString(env, context, "shared", sessionKey);

    if (session_id.empty()) {
        LOGE("Session ID is empty!");
        return "";
    }

    // Get device info strings
    std::string fingerprint = jniutils::getBuildFingerprint(env);
    std::string androidId = jniutils::getAndroidID(env, context);
    std::string hwInfo = jniutils::getDeviceHardwareInfo(env);

    std::time_t now = std::time(nullptr);
    std::string randomStr = randomHexString(16);

    std::stringstream tokenStream;
    tokenStream << session_id << "|"
                << fingerprint << "|"
                << androidId << "|"
                << hwInfo << "|"
                << now << "|"
                << randomStr;

    std::string rawToken = tokenStream.str();

    // SHA256 hash of raw token
    std::string hashed = sha256(rawToken);

    // Encrypt hashed token (dummy AES)
    std::string encrypted = aesEncrypt(hashed, AES_KEY);

    // Convert encrypted binary to hex string
    std::stringstream ss;
    for (unsigned char c : encrypted) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }

    std::string finalToken = ss.str();

    LOGI("Generated token (hex): %s", finalToken.c_str());

    return finalToken;
}

}  // namespace tokencore
