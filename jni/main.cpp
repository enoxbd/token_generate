#include <jni.h>
#include <string>
#include <android/log.h>
#include <time.h>
#include "TokenCore.hpp"

#define LOG_TAG "MainNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// JNI Function: Java theke call hobe
extern "C"
JNIEXPORT jstring JNICALL
Java_com_my_newproject8_SecureManager_getSecureToken(
        JNIEnv* env,
        jobject /* this */,
        jobject context) {

    // Call the token generator with SharedPreferences key "User"
    std::string token = tokencore::generateSecureToken(env, context, "User");
    LOGI("Generated Token: %s", token.c_str());
    return env->NewStringUTF(token.c_str());
}
