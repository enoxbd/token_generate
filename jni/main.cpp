#include <jni.h>
#include <android/log.h>
#include <string>
#include "security_core.hpp"
#include "token_core.hpp"  // তোমার টোকেন জেনারেট ফাংশন

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

    std::string threat_str = detectThreats(env, context);

    if (threat_str != "Safe") {
        LOGI("❌ Threat detected: %s", threat_str.c_str());
        std::string err = "ERROR_THREAT_DETECTED: " + threat_str;
        return env->NewStringUTF(err.c_str());
    }

    std::string token = generateSecureToken(env, context);
    LOGI("✅ Token generated successfully: %s", token.c_str());
    return env->NewStringUTF(token.c_str());
}
