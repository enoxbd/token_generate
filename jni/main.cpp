#include <jni.h>
#include <string>
#include <android/log.h>
#include <cstdlib>
#include <ctime>
#include <unistd.h>  // _exit() এর জন্য
#include "security_core.hpp"
#include "token_core.hpp"

#define LOG_TAG "NativeSecurity"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

extern "C" JNIEXPORT jstring JNICALL
Java_com_my_newproject8_SecureManager_getSecureToken(JNIEnv *env, jobject thiz, jobject context) {
    if (detectFrida() || detectRoot() || detectMagisk() || detectBurpSuite() || detectCanary() || detectMITM() || detectProxy() || detectAppMod()) {
        _exit(0);  // safer than exit()
    }

    std::string sessionId = getSharedPreference(env, context, "User");
    std::string token = generateSecureToken(env, context, sessionId);
    return env->NewStringUTF(token.c_str());
}
