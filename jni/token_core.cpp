#include "token_core.hpp"
#include <android/log.h>
#include <string>
#include <time.h>
#include <cstdlib>
#include "utils.hpp"
#include "sha256_small.hpp"  // তোমার sha256 ফাংশন

#define LOG_TAG "TokenCore"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// SharedPreferences থেকে ডাটা পড়ার ফাংশন (তোমার কোড অনুসারে)
std::string getSP(JNIEnv* env, jobject ctx, const char* name, const char* key) {
    if (!env || !ctx) return "0";

    jclass ctxCls = env->GetObjectClass(ctx);
    if (!ctxCls) return "0";

    jmethodID getSP = env->GetMethodID(ctxCls, "getSharedPreferences", "(Ljava/lang/String;I)Landroid/content/SharedPreferences;");
    if (!getSP) return "0";

    jstring nm = env->NewStringUTF(name);
    jobject sp = env->CallObjectMethod(ctx, getSP, nm, 0);
    env->DeleteLocalRef(nm);

    if (!sp) return "0";

    jclass spCls = env->GetObjectClass(sp);
    if (!spCls) return "0";

    jmethodID getString = env->GetMethodID(spCls, "getString", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
    if (!getString) return "0";

    jstring jk = env->NewStringUTF(key);
    jstring jdef = env->NewStringUTF("0");

    jstring jval = (jstring)env->CallObjectMethod(sp, getString, jk, jdef);

    env->DeleteLocalRef(jk);
    env->DeleteLocalRef(jdef);

    if (!jval) return "0";

    const char* val = env->GetStringUTFChars(jval, 0);
    std::string out(val);
    env->ReleaseStringUTFChars(jval, val);
    env->DeleteLocalRef(jval);

    return out;
}

// Token generate করার মূল ফাংশন
std::string generateSecureToken(JNIEnv* env, jobject ctx) {
    std::string session = getSP(env, ctx, "User", "session_id");
    std::string device = getprop("ro.serialno");
    std::string fp = getprop("ro.build.fingerprint");

    if (session == "0") session = "unknown";
    if (device.empty()) device = "nodevice";
    if (fp.empty()) fp = "nofingerprint";

    long t = time(NULL);

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
