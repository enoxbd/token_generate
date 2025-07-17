#include <jni.h>
#include <string>
#include <android/log.h>
#include <unistd.h>
#include <fstream>
#include <dirent.h>
#include <sys/system_properties.h>
#include <sys/ptrace.h>
#include <cstring>

#define LOG_TAG "SecurityCore"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// getprop function: Android system property থেকে মান নেওয়ার জন্য
std::string getprop(const char* key) {
    char buf[PROP_VALUE_MAX];
    __system_property_get(key, buf);
    return std::string(buf);
}

// Root detection
bool isRooted() {
    const char* paths[] = {"/system/bin/su","/system/xbin/su","/sbin/su",
        "/system/app/Superuser.apk","/system/app/Superuser","/system/xbin/daemonsu"};
    for (auto p : paths) {
        if (access(p, F_OK) == 0) {
            LOGI("Root found: %s", p);
            return true;
        }
    }
    return false;
}

// Frida detection
bool isFrida() {
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        if (line.find("frida") != std::string::npos || line.find("gum-js-loop") != std::string::npos) {
            LOGI("Frida detected");
            return true;
        }
    }
    return false;
}

// Debugger detection
bool isDebug() {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
        LOGI("Debugger attached");
        return true;
    }
    return false;
}

// Proxy detection
bool isProxy() {
    char* p = getenv("http_proxy");
    if (p && (strstr(p, "127.") || strstr(p, "localhost"))) {
        LOGI("Proxy set: %s", p);
        return true;
    }
    return false;
}

// Burp/Canary detection via installed apps path list
bool isBurpCanary() {
    DIR* dir = opendir("/data/data");
    if (!dir) return false; // safety check

    struct dirent* d;
    while ((d = readdir(dir)) != nullptr) {
        std::string n = d->d_name;
        if (n.find("burp") != std::string::npos || n.find("canary") != std::string::npos) {
            closedir(dir);
            LOGI("Burp/Canary pkg found: %s", n.c_str());
            return true;
        }
    }
    closedir(dir);
    return false;
}

// Package name check
bool isWrongPackage(JNIEnv* env, jobject ctx) {
    jclass ctxCls = env->GetObjectClass(ctx);
    jmethodID mid = env->GetMethodID(ctxCls, "getPackageName", "()Ljava/lang/String;");
    jstring jpkg = (jstring)env->CallObjectMethod(ctx, mid);
    const char* pkg = env->GetStringUTFChars(jpkg, 0);

    bool wrong = strcmp(pkg, "com.my.newproject8") != 0;

    env->ReleaseStringUTFChars(jpkg, pkg);
    if (wrong) LOGI("Package mismatch: %s", pkg);

    return wrong;
}

// Emulator detection
bool isEmulator() {
    std::string model = getprop("ro.product.model");
    std::string manufacturer = getprop("ro.product.manufacturer");

    if (model.find("sdk") != std::string::npos || manufacturer.find("Genymotion") != std::string::npos) {
        LOGI("Emulator detected: %s - %s", model.c_str(), manufacturer.c_str());
        return true;
    }
    return false;
}

// Threat detection combined
extern "C"
bool detectThreats(JNIEnv* env, jobject ctx) {
    return isRooted() || isFrida() || isDebug() || isProxy() || isBurpCanary() || isWrongPackage(env, ctx) || isEmulator();
}
