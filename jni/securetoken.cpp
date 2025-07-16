#include <jni.h>
#include <string>
#include <android/log.h>
#include <ctime>
#include <sstream>
#include <iomanip>
#include "sha256_small.hpp"  // আমাদের নিজস্ব SHA256 implementation

#define LOG_TAG "SecureToken"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

std::string sha256(const std::string& input) {
    SHA256_CTX ctx;
    uint8_t hash[32];
    sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t*)input.c_str(), input.size());
    sha256_final(&ctx, hash);

    std::ostringstream os;
    for (int i = 0; i < 32; ++i)
        os << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return os.str();
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
