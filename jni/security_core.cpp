#include "security_core.hpp"
#include <unistd.h>
#include <sys/stat.h>
#include <fstream>
#include <dlfcn.h>
#include <jni.h>
#include <android/log.h>
#include <cstdlib>
#include <string>
#include <vector>

#define LOG_TAG "SecurityCore"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

void exitApp() {
    LOGI("Threat detected. Exiting...");
    _exit(0);
}

// File exists checker
bool fileExists(const char *path) {
    struct stat info;
    return stat(path, &info) == 0;
}

// Root checker
bool isDeviceRooted() {
    const char *paths[] = {
        "/system/xbin/su",
        "/system/bin/su",
        "/system/app/Superuser.apk",
        "/sbin/su",
        "/system/sd/xbin/su",
        "/system/usr/we-need-root/su",
        "/system/bin/.ext/su",
        "/system/xbin/mu",
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",
    };
    for (const char *path : paths) {
        if (fileExists(path)) {
            LOGI("Root detected at: %s", path);
            return true;
        }
    }
    return false;
}

// Debugger checker
bool isBeingDebugged() {
    char buffer[1024];
    FILE *file = fopen("/proc/self/status", "r");
    if (!file) return false;
    while (fgets(buffer, sizeof(buffer), file)) {
        if (strncmp(buffer, "TracerPid:", 10) == 0) {
            int tracerPid = atoi(buffer + 10);
            fclose(file);
            if (tracerPid != 0) {
                LOGI("Debugger detected! TracerPid = %d", tracerPid);
                return true;
            }
            break;
        }
    }
    fclose(file);
    return false;
}

// Frida detection
bool isFridaRunning() {
    void *handle = dlopen("libfrida-gadget.so", RTLD_LAZY);
    if (handle) {
        dlclose(handle);
        LOGI("Frida gadget library detected!");
        return true;
    }
    return false;
}

// Magisk detection
bool isMagiskInstalled() {
    const char *paths[] = {
        "/sbin/magisk",
        "/init.magisk.rc",
        "/system/bin/magisk",
        "/data/adb/magisk.img",
        "/data/adb/magisk",
    };
    for (const char *path : paths) {
        if (fileExists(path)) {
            LOGI("Magisk detected at: %s", path);
            return true;
        }
    }
    return false;
}

// Proxy / Burp / MITM / Canary detection
bool isNetworkProxyEnabled() {
    const char *envVars[] = { "http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY" };
    for (const char *env : envVars) {
        const char *value = getenv(env);
        if (value && strstr(value, "127.0.0.1")) {
            LOGI("Proxy detected in env: %s", value);
            return true;
        }
    }

    // /proc/net/tcp থেকে port 8080 বা 8888 check
    std::ifstream netTcp("/proc/net/tcp");
    std::string line;
    while (getline(netTcp, line)) {
        if (line.find("0100007F") != std::string::npos) { // 127.0.0.1
            if (line.find("1F90") != std::string::npos || line.find("22B8") != std::string::npos) { // 8080 or 8888
                LOGI("MITM proxy port detected in /proc/net/tcp");
                return true;
            }
        }
    }
    return false;
}

// Main secure checker
void performAllSecurityChecks() {
    if (isBeingDebugged()) exitApp();
    if (isDeviceRooted()) exitApp();
    if (isFridaRunning()) exitApp();
    if (isMagiskInstalled()) exitApp();
    if (isNetworkProxyEnabled()) exitApp();
}
