#include "utils.hpp"
#include <android/log.h>
#include <unistd.h>
#include <cstdlib>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <random>
#include <sys/system_properties.h>

#define LOG_TAG "SecureUtils"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// SharedPreferences থেকে session_id নেবে
std::string getSharedPreference(JNIEnv *env, jobject context, const std::string &key) {
    jclass contextClass = env->GetObjectClass(context);
    jmethodID getSharedPreferences = env->GetMethodID(contextClass, "getSharedPreferences",
                                                       "(Ljava/lang/String;I)Landroid/content/SharedPreferences;");
    jobject sharedPrefs = env->CallObjectMethod(context,
        getSharedPreferences,
        env->NewStringUTF("User"),
        0);

    jclass prefsClass = env->GetObjectClass(sharedPrefs);
    jmethodID getString = env->GetMethodID(prefsClass, "getString",
                                           "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
    jstring jKey = env->NewStringUTF(key.c_str());
    jstring defValue = env->NewStringUTF("");
    jstring value = (jstring) env->CallObjectMethod(sharedPrefs, getString, jKey, defValue);

    const char *str = env->GetStringUTFChars(value, 0);
    std::string result(str);
    env->ReleaseStringUTFChars(value, str);
    return result;
}

// Android ID
std::string getDeviceId(JNIEnv *env, jobject context) {
    jclass secureClass = env->FindClass("android/provider/Settings$Secure");
    jmethodID getString = env->GetStaticMethodID(secureClass, "getString",
                                                 "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;");
    jclass contextClass = env->GetObjectClass(context);
    jmethodID getContentResolver = env->GetMethodID(contextClass, "getContentResolver",
                                                    "()Landroid/content/ContentResolver;");
    jobject resolver = env->CallObjectMethod(context, getContentResolver);
    jstring androidId = (jstring) env->CallStaticObjectMethod(secureClass, getString, resolver,
                                                              env->NewStringUTF("android_id"));

    const char *id = env->GetStringUTFChars(androidId, 0);
    std::string result(id);
    env->ReleaseStringUTFChars(androidId, id);
    return result;
}

// Build fingerprint
std::string getDeviceFingerprint(JNIEnv *env) {
    char fingerprint[PROP_VALUE_MAX];
    __system_property_get("ro.build.fingerprint", fingerprint);
    return std::string(fingerprint);
}

// সময়
std::string getCurrentTime() {
    time_t now = time(0);
    std::stringstream ss;
    ss << now;
    return ss.str();
}

// র‍্যান্ডম স্ট্রিং
std::string generateRandomString(int length) {
    const std::string chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, chars.length() - 1);

    std::string result;
    for (int i = 0; i < length; ++i) {
        result += chars[dis(gen)];
    }
    return result;
}
