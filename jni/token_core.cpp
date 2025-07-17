#include <jni.h>
#include <string>
#include <android/log.h>
#include <time.h>
#include <cstdlib>
#include <sys/system_properties.h>
#include <sstream>
#include <iomanip>
#include "utils.hpp"
#include "sha256_small.hpp"  // এখানে sha256 ফাংশন ডিফাইন করা আছে

#define LOG_TAG "TokenCore"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)



// SharedPreferences থেকে ডেটা নেওয়ার ফাংশন
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

// টোকেন জেনারেট করার মূল ফাংশন
std::string generateSecureToken(JNIEnv* env, jobject ctx) {
    std::string session = getSP(env, ctx, "User", "session_id");
    std::string device = getprop("ro.serialno");
    std::string fp = getprop("ro.build.fingerprint");
    long t = time(NULL);  // current UNIX timestamp

    static bool seeded = false;
    if (!seeded) {
        srand(t);
        seeded = true;
    }

    int randv = rand() % 900000 + 100000;

    std::ostringstream ss;
    ss << session << ":" << device << ":" << fp << ":" << randv << ":" << t;
    std::string base = ss.str();
    LOGI("Base string: %s", base.c_str());

    return sha256(base);
}

// JNI export
extern "C"
JNIEXPORT jstring JNICALL
Java_com_my_newproject8_SecureTokenManager_getToken(JNIEnv* env, jobject thiz, jobject context) {
    std::string token = generateSecureToken(env, context);
    return env->NewStringUTF(token.c_str());
}
