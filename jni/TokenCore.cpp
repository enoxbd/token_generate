#include "TokenCore.hpp"
#include "JNIUtils.hpp"
#include <android/log.h>
#include <ctime>
#include <cstdlib>
#include <sstream>
#include <iomanip>
#include "sha256_small.hpp"    // তোমার নিজস্ব SHA256 implementation

#define LOG_TAG "TokenCore"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Nijorsho AES 128-bit key (16 bytes)
static const unsigned char AES_KEY[16] = {'e','n','o','x','b','d','m','o','n','t','a','s','i','r','1','2'};

namespace tokencore {

// forward declare nijorsho AES_encrypt function (নিচে define করব)
std::string aesEncrypt(const std::string& plaintext, const unsigned char* key);

// Helper: Generate random hex string
static std::string randomHexString(size_t length) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        result.push_back(hex_chars[rand() % 16]);
    }
    return result;
}

// Main function: Generate secure token
std::string generateSecureToken(JNIEnv* env, jobject context, const std::string& sessionKey) {
    std::string session_id = jniutils::getSharedPreferenceString(env, context, "User", sessionKey);
    if (session_id.empty()) {
        LOGE("Session ID is empty");
        return "";
    }

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

    // SHA256 হ্যাশ (sha256_small.hpp থেকে)
    std::string hashed = sha256(rawToken);

    // Nijorsho AES এনক্রিপশন (নিচে define করা)
    std::string encrypted = aesEncrypt(hashed, AES_KEY);

    // এনক্রিপ্টেড বাইনারি ডেটাকে হেক্স স্ট্রিং এ কনভার্ট
    std::stringstream ss;
    for (unsigned char c : encrypted) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)c;
    }

    return ss.str();
}


// ----------------------- Nijorsho AES Implementation -----------------------

// AES block size 16 বাইট (128 bit)
constexpr int AES_BLOCK_SIZE = 16;

// সোজা PKCS7 padding যুক্ত ফাংশন
static std::string pkcs7Pad(const std::string& input) {
    int pad_len = AES_BLOCK_SIZE - (input.size() % AES_BLOCK_SIZE);
    std::string padded = input;
    padded.append(pad_len, (char)pad_len);
    return padded;
}

// AES-128-CBC এনক্রিপ্ট করার জন্য তোমার নিজস্ব লজিক এখানে দিবে
// (এখানে একটা placeholder হিসেবে simple XOR ব্যবহার করেছি, 
// অবশ্যই production এ তোমার নিজস্ব AES কোড লাগবে)

static std::string aesEncrypt(const std::string& plaintext, const unsigned char* key) {
    // ১. Padding করো
    std::string padded = pkcs7Pad(plaintext);

    // ২. Initialization Vector (IV) - 16 zero bytes (তুমি random করতে পারো)
    unsigned char iv[AES_BLOCK_SIZE] = {0};

    // ৩. এনক্রিপশন আউটপুট স্ট্রিং (সাইজ padded এর সমান)
    std::string ciphertext(padded.size(), 0);

    // ৪. এখানে তোমার নিজস্ব AES-128-CBC এনক্রিপশন করবে, 
    // উদাহরণস্বরূপ আমি এখানে শুধু একটি dummy XOR দিয়ে দিচ্ছি (বদলাতে হবে)
    for (size_t i = 0; i < padded.size(); i++) {
        // এটা শুধু ডেমো; অবশ্যই strong AES লাইব্রেরি ব্যবহার করো
        ciphertext[i] = padded[i] ^ key[i % AES_BLOCK_SIZE] ^ iv[i % AES_BLOCK_SIZE];
    }

    return ciphertext;
}

}  // namespace tokencore
