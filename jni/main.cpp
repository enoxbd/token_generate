#include <jni.h>
#include <android/log.h>
#include <stdlib.h>

#include "security_core.hpp"  // bool detectThreats(JNIEnv*, jobject)
#include "token_core.hpp"     // std::string generateSecureToken(JNIEnv*, jobject)
#include "utils.hpp"

#define LOG_TAG "MainSecure"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

extern "C"
JNIEXPORT jstring JNICALL
Java_com_my_newproject8_SecureManager_getSecureToken(JNIEnv* env, jobject thiz, jobject context) {
    LOGI("🔐 getSecureToken() called");

    // ✅ Null context check
    if (context == nullptr) {
        LOGI("❌ Context is NULL");
        return env->NewStringUTF("ERROR_NULL_CONTEXT");
    }

    // ✅ Threat detection
    bool threat = detectThreats(env, context);
    if (threat) {
        LOGI("❌ Threat detected. Aborting token generation.");
        return env->NewStringUTF("ERROR_THREAT_DETECTED");
    }

    // ✅ Generate token
    std::string token = generateSecureToken(env, context);
    if (token.empty()) {
        LOGI("❌ Token generation failed (empty string returned)");
        return env->NewStringUTF("ERROR_TOKEN_GENERATION_FAILED");
    }

    // ✅ Success
    LOGI("✅ Token generated: %s", token.c_str());
    return env->NewStringUTF(token.c_str());
}
