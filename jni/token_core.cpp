#include <jni.h>
#include <string>
#include <android/log.h>
#include <time.h>
#include <cstdlib>
#include <sys/system_properties.h>
#include <sstream>
#include <iomanip>
#include "utils.hpp"

#include "sha256_small.hpp"

#define LOG_TAG "TokenCore"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

std::string getprop(const char* key) {
    char buf[PROP_VALUE_MAX];
    __system_property_get(key, buf);
    return std::string(buf);
}

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

std::string generateSecureToken(JNIEnv* env, jobject ctx) {
    std::string session = getSP(env, ctx, "User", "session_id");
    std::string device = getprop("ro.serialno");
    std::string fp = getprop("ro.build.fingerprint");
    long t = (time(NULL) / 10) * 10;

    static bool seeded = false;
    if (!seeded) {
        srand(time(NULL));
        seeded = true;
    }

    int randv = rand() % 900000 + 100000;

    std::ostringstream ss;
    ss << session << ":" << device << ":" << fp << ":" << randv << ":" << t;
    std::string base = ss.str();
    LOGI("Base string: %s", base.c_str());

    return sha256(base);
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_my_newproject8_SecureTokenManager_getToken(JNIEnv* env, jobject thiz, jobject context) {
    std::string token = generateSecureToken(env, context);
    return env->NewStringUTF(token.c_str());
}
