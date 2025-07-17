#include <jni.h>
#include <string>
#include <android/log.h>
#include <time.h>
#include <cstdlib>
#include <sys/system_properties.h>
#include <sstream>
#include <iomanip>

#include "sha256_small.hpp"  // custom sha256 function

#define LOG_TAG "TokenCore"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// getprop function (as before)
std::string getprop(const char* key) {
    char buf[PROP_VALUE_MAX];
    __system_property_get(key, buf);
    return std::string(buf);
}

// get SharedPreferences string (as before)
std::string getSP(JNIEnv* env, jobject ctx, const char* name, const char* key) {
    jclass ctxCls = env->GetObjectClass(ctx);
    jmethodID getSP = env->GetMethodID(ctxCls, "getSharedPreferences", "(Ljava/lang/String;I)Landroid/content/SharedPreferences;");
    jstring nm = env->NewStringUTF(name);
    jobject sp = env->CallObjectMethod(ctx, getSP, nm, 0);

    jclass spCls = env->GetObjectClass(sp);
    jmethodID getString = env->GetMethodID(spCls, "getString", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
    jstring jk = env->NewStringUTF(key);
    jstring jdef = env->NewStringUTF("0");
    jstring jval = (jstring)env->CallObjectMethod(sp, getString, jk, jdef);

    const char* val = env->GetStringUTFChars(jval, 0);
    std::string out(val);
    env->ReleaseStringUTFChars(jval, val);
    return out;
}

// generate SHA256 hash using sha256_small.hpp function
std::string sha256(const std::string& data) {
    // sha256_small.hpp defines a function sha256(const std::string&)
    return sha256(data);
}

// generate secure token
std::string generateSecureToken(JNIEnv* env, jobject ctx) {
    std::string session = getSP(env, ctx, "User", "session_id");
    std::string device = getprop("ro.serialno");
    std::string fp = getprop("ro.build.fingerprint");
    long t = (time(NULL) / 10) * 10;
    int randv = rand() % 900000 + 100000;

    std::ostringstream ss;
    ss << session << ":" << device << ":" << fp << ":" << randv << ":" << t;
    std::string base = ss.str();
    LOGI("Base string: %s", base.c_str());

    return sha256(base);
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_my_newproject8_SecureTokenManager_getToken(JNIEnv* env, jobject thiz) {
    std::string token = generateSecureToken(env, thiz);
    return env->NewStringUTF(token.c_str());
}
