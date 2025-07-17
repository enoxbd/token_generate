#include <jni.h>
#include <android/log.h>
#include <stdlib.h>

#include "security_core.hpp"  // এখানে detectThreats এর প্রোটোটাইপ আছে
#include "token_core.hpp"
#include "utils.hpp"

#define LOG_TAG "MainSecure"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

#define SO_PATH "/data/data/com.my.newproject8/lib/libsecure_native.so"

extern "C"
JNIEXPORT jstring JNICALL
Java_com_my_newproject8_SecureManager_getSecureToken(JNIEnv* env, jobject thiz, jobject context) {
    FILE* f = fopen(SO_PATH, "r");
    if (!f) {
        LOGI("SO file missing! Exiting...");
        exit(0);
    }
    fclose(f);

    if (detectThreats(env, context)) {
        LOGI("Threat found! Exiting...");
        exit(0);
    }

    std::string token = generateSecureToken(env, context);
    return env->NewStringUTF(token.c_str());
}
