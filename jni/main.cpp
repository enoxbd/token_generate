#include <jni.h>
#include <string>
#include <android/log.h>
#include "TokenCore.hpp"  // তোমার token generate করার ফাংশন ডিফাইন করা আছে

#define LOG_TAG "NativeSecure"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

extern "C"
JNIEXPORT jstring JNICALL
Java_com_my_newproject8_SecureManager_getSecureTokenNative(
        JNIEnv* env,
        jobject /* this */,
        jstring sessionId) {

    // Java থেকে sessionId নিয়ে আসা
    const char* sessionIdCStr = env->GetStringUTFChars(sessionId, nullptr);
    std::string sessionIdStr(sessionIdCStr);
    env->ReleaseStringUTFChars(sessionId, sessionIdCStr);

    LOGI("Received sessionId: %s", sessionIdStr.c_str());

    // Token তৈরি করার ফাংশন কল করা
    std::string token = tokencore::generateSecureToken(sessionIdStr);

    LOGI("Generated Token: %s", token.c_str());

    return env->NewStringUTF(token.c_str());
}
