#include <jni.h>
#include <string>
#include <android/log.h>
#include "TokenCore.hpp"

#define LOG_TAG "TokenGen"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

std::string getSharedPrefString(JNIEnv* env, jobject context, const std::string& key) {
    jclass ctxClass = env->GetObjectClass(context);
    jmethodID getSharedPref = env->GetMethodID(ctxClass, "getSharedPreferences", "(Ljava/lang/String;I)Landroid/content/SharedPreferences;");
    jobject sharedPref = env->CallObjectMethod(context, getSharedPref, env->NewStringUTF("User"), 0);

    jclass prefClass = env->GetObjectClass(sharedPref);
    jmethodID getString = env->GetMethodID(prefClass, "getString", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
    jstring value = (jstring) env->CallObjectMethod(sharedPref, getString, env->NewStringUTF(key.c_str()), env->NewStringUTF(""));
    
    const char* chars = env->GetStringUTFChars(value, nullptr);
    std::string result(chars);
    env->ReleaseStringUTFChars(value, chars);
    return result;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_my_newproject8_SecureManager_getSecureToken(JNIEnv* env, jclass clazz, jobject context) {
    std::string sessionId = getSharedPrefString(env, context, "User");
    std::string deviceId = getSharedPrefString(env, context, "device_id");

    std::string token = generateSecureToken(sessionId, deviceId);
    return env->NewStringUTF(token.c_str());
}
