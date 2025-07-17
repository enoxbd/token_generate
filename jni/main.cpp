#include <jni.h>
#include <string>
#include "token_core.hpp"

extern "C"
JNIEXPORT jstring JNICALL
Java_com_my_newproject8_SecureManager_getSecureToken(JNIEnv *env, jobject thiz, jobject context) {
    // Call Java to get SharedPreferences values
    jclass contextClass = env->GetObjectClass(context);
    jmethodID getSharedPreferences = env->GetMethodID(contextClass, "getSharedPreferences", "(Ljava/lang/String;I)Landroid/content/SharedPreferences;");
    jobject pref = env->CallObjectMethod(context, getSharedPreferences, env->NewStringUTF("User"), 0);

    jclass prefClass = env->GetObjectClass(pref);
    jmethodID getString = env->GetMethodID(prefClass, "getString", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");

    jstring jSession = (jstring) env->CallObjectMethod(pref, getString, env->NewStringUTF("session_id"), env->NewStringUTF(""));
    jstring jDevice = (jstring) env->CallObjectMethod(pref, getString, env->NewStringUTF("device_id"), env->NewStringUTF(""));

    const char* session = env->GetStringUTFChars(jSession, 0);
    const char* device = env->GetStringUTFChars(jDevice, 0);

    std::string token = generateSecureToken(session, device);

    env->ReleaseStringUTFChars(jSession, session);
    env->ReleaseStringUTFChars(jDevice, device);

    return env->NewStringUTF(token.c_str());
}
