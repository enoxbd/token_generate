#include <jni.h>
#include <string>
#include <android/log.h>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <openssl/sha.h> // ⚠️ এটা বাদ দিতে চাইলে নিচে Native hash function দাও

#define LOG_TAG "SecureToken"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// Simple SHA256 implementation using NDK (or write own version if OpenSSL not present)
std::string sha256(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_my_newproject8_SecureTokenManager_generateSecureToken(JNIEnv *env, jobject thiz) {
    std::string seasonId = "USER_SEASON_ID";
    std::string deviceId = "ANDROID_DEVICE_ID";
    std::string fingerprint = "MODEL_BOARD";
    std::string uniqueId = fingerprint + "_" + std::to_string(time(NULL));
    long t = (time(NULL) / 10) * 10;
    std::string timeStr = std::to_string(t);

    std::string base = seasonId + ":" + deviceId + ":" + fingerprint + ":" + uniqueId + ":" + timeStr;
    LOGI("Base String: %s", base.c_str());

    std::string token = sha256(base);
    return env->NewStringUTF(token.c_str());
}
