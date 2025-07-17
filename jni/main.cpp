#include <jni.h>
#include <android/log.h>
#include <stdlib.h>

#include "security_core.hpp"
#include "token_core.hpp"
#include "utils.hpp"

#define LOG_TAG "MainSecure"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

#define SO_PATH "/data/data/com.my.newproject8/lib/libsecure_native.so"

// detectThreats এর extern "C" প্রোটোটাইপ
extern "C" bool detectThreats(JNIEnv* env, jobject ctx);

extern "C"
JNIEXPORT jstring JNICALL
Java_com_my_newproject8_SecureManager_getSecureToken(JNIEnv* env, jobject thiz, jobject context) {
    // SO ফাইল আছে কিনা চেক
    FILE* f = fopen(SO_PATH, "r");
    if (!f) {
        LOGI("SO file missing! Exiting...");
        exit(0);
    }
    fclose(f);

    // থ্রেট ডিটেকশন
    if (detectThreats(env, context)) {
        LOGI("Threat found! Exiting...");
        exit(0);
    }

    // সিকিউর টোকেন জেনারেশন
    std::string token = generateSecureToken(env, context);
    return env->NewStringUTF(token.c_str());
}
