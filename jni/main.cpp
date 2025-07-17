#include <jni.h>
#include <android/log.h>
#include <string>
#include "security_core.hpp"
#include "token_core.hpp"  // তোমার generateSecureToken ফাংশন এখানে

#define LOG_TAG "MainSecure"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

extern "C"
JNIEXPORT jstring JNICALL
Java_com_my_newproject8_SecureManager_getSecureToken(JNIEnv* env, jobject thiz, jobject context) {
    LOGI("🔐 getSecureToken() called");

    if (context == nullptr) {
        LOGI("❌ Context is NULL");
        return env->NewStringUTF("ERROR_NULL_CONTEXT");
    }

    const char* threat = detectThreats(env, context);
    if (strcmp(threat, "Safe") != 0) {
        LOGI("❌ Threat detected: %s", threat);
        return env->NewStringUTF("ERROR_THREAT_DETECTED");
    }

    std::string token;
    try {
        token = generateSecureToken(env, context);
    } catch (...) {
        LOGI("❌ Exception during token generation");
        return env->NewStringUTF("ERROR_TOKEN_GENERATION_FAILED");
    }

    LOGI("✅ Token generated successfully: %s", token.c_str());
    return env->NewStringUTF(token.c_str());
}
