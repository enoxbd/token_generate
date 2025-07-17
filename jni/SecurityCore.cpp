#include "SecurityCore.hpp"
#include "JNIUtils.hpp"
#include <android/log.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <sys/system_properties.h>  // Added for PROP_VALUE_MAX

#define LOG_TAG "SecurityCore"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#ifndef PROP_VALUE_MAX
#define PROP_VALUE_MAX 92
#endif

namespace securitycore {

static std::string g_packageName = "";
static jobject g_context = nullptr;

static void logAndExit(const char* reason) {
    LOGE("Security Threat Detected: %s", reason);
    _exit(1);
}

void initialize(JNIEnv* env, jobject context, const std::string& packageName) {
    g_packageName = packageName;
    if (g_context != nullptr) {
        env->DeleteGlobalRef(g_context);
    }
    g_context = env->NewGlobalRef(context);
    LOGI("SecurityCore initialized with package: %s", packageName.c_str());
}

bool checkForSuspiciousFiles(const std::string& path) {
    struct stat st;
    return stat(path.c_str(), &st) == 0;
}

// Root detection
bool detectRoot(JNIEnv* env) {
    const char* suPaths[] = {
        "/system/app/Superuser.apk",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su"
    };

    for (const char* path : suPaths) {
        if (checkForSuspiciousFiles(path)) {
            logAndExit("Root detected: su binary found");
            return true;
        }
    }

    jstring buildTags = nullptr;
    {
        jclass buildClass = env->FindClass("android/os/Build");
        jfieldID tagsField = env->GetStaticFieldID(buildClass, "TAGS", "Ljava/lang/String;");
        buildTags = (jstring) env->GetStaticObjectField(buildClass, tagsField);
    }

    if (buildTags) {
        const char* tagsStr = env->GetStringUTFChars(buildTags, nullptr);
        if (tagsStr) {
            std::string tags(tagsStr);
            env->ReleaseStringUTFChars(buildTags, tagsStr);
            if (tags.find("test-keys") != std::string::npos) {
                logAndExit("Root detected: test-keys in build tags");
                return true;
            }
        }
    }

    char roDebuggable[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.debuggable", roDebuggable);
    if (strcmp(roDebuggable, "1") == 0) {
        logAndExit("Root detected: ro.debuggable=1");
        return true;
    }

    if (access("/system/app/Superuser.apk", F_OK) == 0) {
        logAndExit("Root detected: Superuser.apk present");
        return true;
    }

    return false;
}

// Debugger detection
bool detectDebugger() {
    int result = ptrace(PTRACE_TRACEME, 0, nullptr, 0);
    if (result == -1) {
        logAndExit("Debugger detected: ptrace failed");
        return true;
    }

    FILE* statusFile = fopen("/proc/self/status", "r");
    if (!statusFile) return false;

    char line[256];
    while (fgets(line, sizeof(line), statusFile)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int tracerPid = atoi(line + 10);
            fclose(statusFile);
            if (tracerPid != 0) {
                logAndExit("Debugger detected: TracerPid != 0");
                return true;
            }
            break;
        }
    }
    fclose(statusFile);
    return false;
}

// Frida detection
bool detectFrida() {
    FILE* f = fopen("/proc/net/tcp", "r");
    if (!f) return false;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "0100007F:") != nullptr) {
            if (strstr(line, "6A5A") != nullptr || strstr(line, "27042") != nullptr) {
                fclose(f);
                logAndExit("Frida detected: suspicious local TCP port");
                return true;
            }
        }
    }
    fclose(f);

    std::ifstream mapsFile("/proc/self/maps");
    std::string mapsLine;
    while (std::getline(mapsFile, mapsLine)) {
        if (mapsLine.find("frida") != std::string::npos) {
            logAndExit("Frida detected: frida module loaded");
            return true;
        }
    }

    return false;
}

// Magisk detection
bool detectMagisk() {
    const char* magiskPaths[] = {
        "/sbin/magisk",
        "/sbin/.magisk",
        "/data/adb/magisk",
        "/data/adb/magisk.db",
        "/cache/magisk.log",
        "/dev/magisk"
    };

    for (const char* path : magiskPaths) {
        if (checkForSuspiciousFiles(path)) {
            logAndExit("Magisk detected: magisk file found");
            return true;
        }
    }

    if (getenv("MAGISK_VER") != nullptr || getenv("MAGISK_LOG") != nullptr) {
        logAndExit("Magisk detected: env var found");
        return true;
    }

    return false;
}

// API capture detection
bool detectApiCapture(JNIEnv* env) {
    jclass systemClass = env->FindClass("java/lang/System");
    if (!systemClass) return false;

    jmethodID getPropertyMethod = env->GetStaticMethodID(systemClass, "getProperty", "(Ljava/lang/String;)Ljava/lang/String;");
    if (!getPropertyMethod) return false;

    jstring httpProxyHost = (jstring)env->CallStaticObjectMethod(systemClass, getPropertyMethod, env->NewStringUTF("http.proxyHost"));
    jstring httpsProxyHost = (jstring)env->CallStaticObjectMethod(systemClass, getPropertyMethod, env->NewStringUTF("https.proxyHost"));

    if (httpProxyHost || httpsProxyHost) {
        logAndExit("API Capture Detected: Proxy settings found");
        return true;
    }

    return false;
}

} // namespace securitycore
