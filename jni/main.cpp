#include <jni.h>
#include <android/log.h>
#include <stdlib.h>

#include "security_core.hpp"  // detectThreats()
#include "token_core.hpp"
#include "utils.hpp"

#define LOG_TAG "MainSecure"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

extern "C"
JNIEXPORT jstring JNICALL
Java_com_my_newproject8_SecureManager_getSecureToken(JNIEnv* env, jobject thiz, jobject context) {
    LOGI("🔐 getSecureToken() called");

    // ✅ Context null check
    if (context == nullptr) {
        LOGI("❌ Context is NULL");
        return env->NewStringUTF("ERROR_NULL_CONTEXT");
    }

    // ✅ Run threat detection
    bool threat = false;
    try {
        threat = detectThreats(env, context);
    } catch (...) {
        LOGI("❌ Exception during detectThreats()");
        return env->NewStringUTF("ERROR_DETECT_THREATS_FAILED");
    }

    if (threat) {
        LOGI("❌ Threat detected by native code");
        return env->NewStringUTF("ERROR_THREAT_DETECTED");
    }

    // ✅ Generate token safely
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
