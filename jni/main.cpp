#include <jni.h>
#include <string>
#include <android/log.h>
#include "TokenCore.hpp"

#define LOG_TAG "NativeSecure"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// JNI function called from Java:
// Signature: getSecureTokenNative(Context context, String sessionId)
extern "C"
JNIEXPORT jstring JNICALL
Java_com_my_newproject8_SecureManager_getSecureTokenNative(
        JNIEnv* env,
        jobject /* this */,
        jobject context,
        jstring sessionId) {

    if (context == nullptr || sessionId == nullptr) {
        LOGE("Context or sessionId is null");
        return env->NewStringUTF("");
    }

    // Convert jstring sessionId to std::string
    const char* sessionIdCStr = env->GetStringUTFChars(sessionId, nullptr);
    if (!sessionIdCStr) {
        LOGE("Failed to get UTF chars from sessionId");
        return env->NewStringUTF("");
    }
    std::string sessionIdStr(sessionIdCStr);
    env->ReleaseStringUTFChars(sessionId, sessionIdCStr);

    LOGI("Received sessionId: %s", sessionIdStr.c_str());

    // Generate token by passing env, context, and sessionIdStr
    std::string token = tokencore::generateSecureToken(env, context, sessionIdStr);

    if (token.empty()) {
        LOGE("Generated token is empty");
    } else {
        LOGI("Generated token: %s", token.c_str());
    }

    return env->NewStringUTF(token.c_str());
}
