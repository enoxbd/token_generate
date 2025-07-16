#include <jni.h>
#include <string>
#include <android/log.h>
#include <openssl/sha.h>
#include <time.h>
#include <cstdlib>
#include <sys/system_properties.h>
#include <sstream>
#include <iomanip>

#define LOG_TAG "TokenCore"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// Android system property getter
std::string getprop(const char* key) {
    char buf[PROP_VALUE_MAX];
    __system_property_get(key, buf);
    return std::string(buf);
}

// SharedPreferences থেকে মান নেওয়া
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

// SHA256 hash function
std::string sha256(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)data.c_str(), data.size(), hash);
    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return oss.str();
}

// Secure Token Generator
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

// JNI method
extern "C"
JNIEXPORT jstring JNICALL
Java_com_my_newproject8_SecureTokenManager_getToken(JNIEnv *env, jobject thiz) {
    return env->NewStringUTF(generateSecureToken(env, thiz).c_str());
}
