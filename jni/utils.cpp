#include "utils.hpp"
#include <jni.h>
#include <string>
#include <ctime>
#include <cstdlib>
#include <random>
#include <android/log.h>
#include <sys/system_properties.h>

#define LOG_TAG "Utils"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// SharedPreferences থেকে session_id নেয়া
std::string getSharedPreference(JNIEnv *env, jobject context, const std::string &key) {
    jclass ctxCls = env->GetObjectClass(context);
    jmethodID getSharedPrefsMethod = env->GetMethodID(ctxCls, "getSharedPreferences", "(Ljava/lang/String;I)Landroid/content/SharedPreferences;");
    jobject prefs = env->CallObjectMethod(context, getSharedPrefsMethod, env->NewStringUTF("User"), 0);

    jclass prefsCls = env->GetObjectClass(prefs);
    jmethodID getStringMethod = env->GetMethodID(prefsCls, "getString", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
    jstring jValue = (jstring)env->CallObjectMethod(prefs, getStringMethod, env->NewStringUTF(key.c_str()), nullptr);

    if (jValue == nullptr) {
        return "";
    }

    const char *value = env->GetStringUTFChars(jValue, nullptr);
    std::string result(value);
    env->ReleaseStringUTFChars(jValue, value);
    return result;
}

// Android ID নেওয়া
std::string getDeviceId(JNIEnv *env, jobject context) {
    jclass contextClass = env->GetObjectClass(context);
    jmethodID getContentResolverMethod = env->GetMethodID(contextClass, "getContentResolver", "()Landroid/content/ContentResolver;");
    jobject contentResolver = env->CallObjectMethod(context, getContentResolverMethod);

    jclass settingsSecureClass = env->FindClass("android/provider/Settings$Secure");
    jmethodID getStringMethod = env->GetStaticMethodID(settingsSecureClass, "getString",
        "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;");
    jstring androidIdString = (jstring)env->CallStaticObjectMethod(settingsSecureClass, getStringMethod, contentResolver, env->NewStringUTF("android_id"));

    const char *androidId = env->GetStringUTFChars(androidIdString, nullptr);
    std::string deviceId(androidId);
    env->ReleaseStringUTFChars(androidIdString, androidId);

    return deviceId;
}

// Fingerprint নেওয়া
std::string getDeviceFingerprint(JNIEnv *env) {
    char fingerprint[PROP_VALUE_MAX];
    __system_property_get("ro.build.fingerprint", fingerprint);
    return std::string(fingerprint);
}

// বর্তমান UNIX timestamp
std::string getCurrentTime() {
    std::time_t t = std::time(nullptr);
    return std::to_string(t);
}

// র‍্যান্ডম স্ট্রিং জেনারেটর
std::string generateRandomString(int length) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    std::string result;
    std::random_device rd;
    std::mt19937 engine(rd());
    std::uniform_int_distribution<> dist(0, sizeof(alphanum) - 2);

    for (int i = 0; i < length; ++i) {
        result += alphanum[dist(engine)];
    }

    return result;
}
