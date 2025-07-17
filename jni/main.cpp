#include <jni.h>
#include <string>
#include <android/log.h>
#include <cstdlib>
#include <unistd.h>            // _exit() এর জন্য অবশ্যই লাগবে
#include "security_core.hpp"
#include "token_core.hpp"
#include "utils.hpp"

#define LOG_TAG "NativeSecurity"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

extern "C" JNIEXPORT jstring JNICALL
Java_com_my_newproject8_SecureManager_getSecureToken(JNIEnv *env, jobject thiz, jobject context) {
    // Threat detect: যদি কোন হুমকি পাওয়া যায়, অ্যাপ native থেকে exit করবে
    if (detectFrida() || detectRoot() || detectMagisk() || detectBurpSuite() || detectCanary() || detectMITM() || detectProxy()) {
        _exit(0);  // safer exit
    }

    // SharedPreferences থেকে sessionId নাও
    std::string sessionId = getSharedPreference(env, context, "User");
    if (sessionId.empty()) {
        LOGI("Session ID is empty");
        return env->NewStringUTF("");
    }

    // Token generate করো
    std::string token = generateSecureToken(sessionId);

    // Java তে return করো
    return env->NewStringUTF(token.c_str());
}
