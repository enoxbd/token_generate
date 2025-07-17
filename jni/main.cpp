#include <jni.h>
#include <string>
#include <android/log.h>
#include <cstdlib>
#include "security_core.hpp"
#include "token_core.hpp"
#include "utils.hpp"   // getSharedPreference-এর জন্য

#define LOG_TAG "NativeSecurity"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

extern "C" JNIEXPORT jstring JNICALL
Java_com_my_newproject8_SecureManager_getSecureToken(JNIEnv *env, jobject thiz, jobject context) {
    // Threat detect: যদি কোন হুমকি পাওয়া যায়, অ্যাপ বন্ধ করে দাও
    if (detectFrida() || detectRoot() || detectMagisk() || detectBurpSuite() || detectCanary() || detectMITM() || detectProxy() /*|| detectAppMod()*/) {
        _exit(0);  // safer exit than exit(0)
    }

    // SharedPreferences থেকে sessionId নাও
    std::string sessionId = getSharedPreference(env, context, "User");
    if (sessionId.empty()) {
        LOGI("Session ID is empty");
        return env->NewStringUTF("");
    }

    // generateSecureToken ফাংশন কল করো (sessionId থেকে token তৈরী করে)
    std::string token = generateSecureToken(sessionId);

    // Java তে return করো
    return env->NewStringUTF(token.c_str());
}
