#include "utils.hpp"
#include <android/log.h>
#include <ctime>
#include <random>

#define LOG_TAG "JNIUtils"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// SharedPreferences থেকে key-এর মান পড়া
std::string getSharedPreference(JNIEnv *env, jobject context, const std::string &key) {
    jclass contextClass = env->GetObjectClass(context);
    jmethodID getSharedPreferences = env->GetMethodID(contextClass, "getSharedPreferences", 
        "(Ljava/lang/String;I)Landroid/content/SharedPreferences;");
    jobject sharedPref = env->CallObjectMethod(context, getSharedPreferences, 
        env->NewStringUTF("shared"), 0); // MODE_PRIVATE = 0

    jclass prefClass = env->GetObjectClass(sharedPref);
    jmethodID getString = env->GetMethodID(prefClass, "getString", 
        "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");

    jstring jValue = (jstring)env->CallObjectMethod(sharedPref, getString, 
        env->NewStringUTF(key.c_str()), env->NewStringUTF(""));

    const char *value = env->GetStringUTFChars(jValue, nullptr);
    std::string result(value);
    env->ReleaseStringUTFChars(jValue, value);
    return result;
}

// ANDROID_ID
std::string getDeviceId(JNIEnv *env, jobject context) {
    jclass settingsSecure = env->FindClass("android/provider/Settings$Secure");
    jmethodID getString = env->GetStaticMethodID(settingsSecure, "getString", 
        "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;");

    jclass contextClass = env->GetObjectClass(context);
    jmethodID getContentResolver = env->GetMethodID(contextClass, "getContentResolver", 
        "()Landroid/content/ContentResolver;");
    jobject contentResolver = env->CallObjectMethod(context, getContentResolver);

    jstring androidId = (jstring)env->CallStaticObjectMethod(settingsSecure, getString,
        contentResolver, env->NewStringUTF("android_id"));

    const char *value = env->GetStringUTFChars(androidId, nullptr);
    std::string result(value);
    env->ReleaseStringUTFChars(androidId, value);
    return result;
}

// FINGERPRINT
std::string getDeviceFingerprint(JNIEnv *env) {
    jclass buildClass = env->FindClass("android/os/Build");
    jfieldID fingerprintField = env->GetStaticFieldID(buildClass, "FINGERPRINT", "Ljava/lang/String;");
    jstring fingerprint = (jstring)env->GetStaticObjectField(buildClass, fingerprintField);

    const char *value = env->GetStringUTFChars(fingerprint, nullptr);
    std::string result(value);
    env->ReleaseStringUTFChars(fingerprint, value);
    return result;
}

// CURRENT TIME
std::string getCurrentTime() {
    time_t now = time(0);
    return std::to_string(now);
}

// RANDOM STRING
std::string generateRandomString(int length) {
    const char charset[] = "0123456789abcdef";
    std::string result;
    std::random_device rd;
    std::mt19937 gen(rd());

    for (int i = 0; i < length; ++i) {
        result += charset[gen() % (sizeof(charset) - 1)];
    }
    return result;
}
