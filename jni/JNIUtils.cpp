#include "JNIUtils.hpp"
#include <android/log.h>

#define LOG_TAG "SecurityCore"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace jniutils {

std::string getSharedPreferenceString(JNIEnv* env,
                                     jobject context,
                                     const std::string& prefName,
                                     const std::string& key) {
    std::string result = "";

    jclass contextClass = env->GetObjectClass(context);
    jmethodID getSharedPreferencesMethod = env->GetMethodID(
        contextClass, "getSharedPreferences",
        "(Ljava/lang/String;I)Landroid/content/SharedPreferences;");
    if (!getSharedPreferencesMethod) {
        LOGE("Failed to find getSharedPreferences method");
        return "";
    }

    jstring jPrefName = env->NewStringUTF(prefName.c_str());
    jobject sharedPreferences = env->CallObjectMethod(context, getSharedPreferencesMethod, jPrefName, 0);
    env->DeleteLocalRef(jPrefName);

    if (!sharedPreferences) {
        LOGE("Failed to get SharedPreferences object");
        return "";
    }

    jclass sharedPrefsClass = env->GetObjectClass(sharedPreferences);
    jmethodID getStringMethod = env->GetMethodID(
        sharedPrefsClass, "getString",
        "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
    if (!getStringMethod) {
        LOGE("Failed to find SharedPreferences.getString method");
        env->DeleteLocalRef(sharedPreferences);
        return "";
    }

    jstring jKey = env->NewStringUTF(key.c_str());
    jstring jDefault = env->NewStringUTF("");
    jstring jValue = (jstring) env->CallObjectMethod(sharedPreferences, getStringMethod, jKey, jDefault);

    env->DeleteLocalRef(jKey);
    env->DeleteLocalRef(jDefault);

    if (jValue) {
        const char* strChars = env->GetStringUTFChars(jValue, nullptr);
        if (strChars) {
            result = std::string(strChars);
            env->ReleaseStringUTFChars(jValue, strChars);
        }
        env->DeleteLocalRef(jValue);
    }

    env->DeleteLocalRef(sharedPreferences);
    return result;
}

std::string getAndroidID(JNIEnv* env, jobject context) {
    std::string androidID = "";

    jclass secureClass = env->FindClass("android/provider/Settings$Secure");
    if (!secureClass) {
        LOGE("Failed to find Settings$Secure class");
        return "";
    }

    jmethodID getStringMethod = env->GetStaticMethodID(
        secureClass, "getString",
        "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;");
    if (!getStringMethod) {
        LOGE("Failed to find Settings$Secure.getString method");
        return "";
    }

    jclass contextClass = env->GetObjectClass(context);
    jmethodID getContentResolverMethod = env->GetMethodID(
        contextClass, "getContentResolver", "()Landroid/content/ContentResolver;");
    if (!getContentResolverMethod) {
        LOGE("Failed to find Context.getContentResolver method");
        return "";
    }

    jobject contentResolver = env->CallObjectMethod(context, getContentResolverMethod);
    jstring androidIDStr = env->NewStringUTF("android_id");

    jstring resultString = (jstring) env->CallStaticObjectMethod(
        secureClass, getStringMethod, contentResolver, androidIDStr);

    env->DeleteLocalRef(androidIDStr);

    if (resultString) {
        const char* strChars = env->GetStringUTFChars(resultString, nullptr);
        if (strChars) {
            androidID = std::string(strChars);
            env->ReleaseStringUTFChars(resultString, strChars);
        }
        env->DeleteLocalRef(resultString);
    }

    return androidID;
}

std::string getBuildFingerprint(JNIEnv* env) {
    std::string fingerprint = "";
    jclass buildClass = env->FindClass("android/os/Build");
    if (!buildClass) {
        LOGE("Failed to find android.os.Build class");
        return "";
    }

    jfieldID fingerprintField = env->GetStaticFieldID(buildClass, "FINGERPRINT", "Ljava/lang/String;");
    if (!fingerprintField) {
        LOGE("Failed to find Build.FINGERPRINT field");
        return "";
    }

    jstring fingerprintStr = (jstring) env->GetStaticObjectField(buildClass, fingerprintField);
    if (fingerprintStr) {
        const char* strChars = env->GetStringUTFChars(fingerprintStr, nullptr);
        if (strChars) {
            fingerprint = std::string(strChars);
            env->ReleaseStringUTFChars(fingerprintStr, strChars);
        }
        env->DeleteLocalRef(fingerprintStr);
    }

    return fingerprint;
}

std::string getDeviceHardwareInfo(JNIEnv* env) {
    std::string info = "";

    jclass buildClass = env->FindClass("android/os/Build");
    if (!buildClass) {
        LOGE("Failed to find android.os.Build class");
        return "";
    }

    jfieldID manufacturerField = env->GetStaticFieldID(buildClass, "MANUFACTURER", "Ljava/lang/String;");
    jfieldID modelField = env->GetStaticFieldID(buildClass, "MODEL", "Ljava/lang/String;");
    if (!manufacturerField || !modelField) {
        LOGE("Failed to find MANUFACTURER or MODEL field");
        return "";
    }

    jstring manufacturerStr = (jstring) env->GetStaticObjectField(buildClass, manufacturerField);
    jstring modelStr = (jstring) env->GetStaticObjectField(buildClass, modelField);

    std::string manufacturer = "";
    std::string model = "";

    if (manufacturerStr) {
        const char* mChars = env->GetStringUTFChars(manufacturerStr, nullptr);
        if (mChars) {
            manufacturer = std::string(mChars);
            env->ReleaseStringUTFChars(manufacturerStr, mChars);
        }
        env->DeleteLocalRef(manufacturerStr);
    }

    if (modelStr) {
        const char* mChars = env->GetStringUTFChars(modelStr, nullptr);
        if (mChars) {
            model = std::string(mChars);
            env->ReleaseStringUTFChars(modelStr, mChars);
        }
        env->DeleteLocalRef(modelStr);
    }

    info = manufacturer + "_" + model;
    return info;
}

} // namespace jniutils
