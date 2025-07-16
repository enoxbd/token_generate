#include <jni.h>
#include <string>
#include <android/log.h>
#include <openssl/sha.h>
#include <time.h>

#define LOG_TAG "SecureToken"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

std::string sha256(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)data.c_str(), data.size(), hash);
    char buf[2*SHA256_DIGEST_LENGTH+1];
    for(int i=0; i < SHA256_DIGEST_LENGTH; ++i) {
        sprintf(buf + i*2, "%02x", hash[i]);
    }
    return std::string(buf);
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_my_newproject8_SecureTokenManager_generateSecureToken(JNIEnv* env, jobject thiz) {
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