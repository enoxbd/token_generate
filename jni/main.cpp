#include <jni.h>
#include <android/log.h>
#include <stdlib.h>

#include "security_core.hpp"  // header ফাইল include করো
#include "token_core.hpp"     // header ফাইল include করো

#define LOG_TAG "MainSecure"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// Application package name অনুযায়ী SO ফাইলের path
#define SO_PATH "/data/data/com.my.newproject8/lib/libsecure_native.so"

extern "C"
JNIEXPORT jstring JNICALL
Java_com_my_newproject8_SecureManager_getSecureToken(JNIEnv* env, jobject thiz, jobject context) {
    // ১) SO file exists check
    FILE* f = fopen(SO_PATH, "r");
    if (!f) {
        LOGI("SO file missing! Exiting...");
        exit(0);
    }
    fclose(f);

    // ২) Core security checks
    if (detectThreats(env, context)) {
        LOGI("Threat found! Exiting...");
        exit(0);
    }

    // ৩) Valid shortcut token generation
    std::string token = generateSecureToken(env, context);
    return env->NewStringUTF(token.c_str());
}
