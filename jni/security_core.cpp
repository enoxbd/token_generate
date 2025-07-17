#include "security_core.hpp"
#include <unistd.h>       // _exit()
#include <android/log.h>
#include <sys/stat.h>
#include <fstream>
#include <dlfcn.h>
#include <cstring>
#include <cstdlib>

#define LOG_TAG "SecurityCore"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// Helper: ফাইল আছে কিনা চেক
static bool fileExists(const char *path) {
    struct stat info;
    return stat(path, &info) == 0;
}

// Root detect
bool detectRoot() {
    const char *paths[] = {
        "/system/xbin/su", "/system/bin/su", "/system/app/Superuser.apk",
        "/sbin/su", "/system/sd/xbin/su", "/system/usr/we-need-root/su",
        "/system/bin/.ext/su", "/system/xbin/mu",
        "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su"
    };
    for (const char *p : paths) {
        if (fileExists(p)) {
            LOGI("Root detected at: %s", p);
            return true;
        }
    }
    return false;
}

// Frida detect (libfrida-gadget.so presence)
bool detectFrida() {
    void *handle = dlopen("libfrida-gadget.so", RTLD_NOW);
    if (handle) {
        dlclose(handle);
        LOGI("Frida detected!");
        return true;
    }
    return false;
}

// Magisk detect (common magisk files)
bool detectMagisk() {
    const char *paths[] = {
        "/sbin/magisk", "/init.magisk.rc", "/system/bin/magisk",
        "/data/adb/magisk.img", "/data/adb/magisk"
    };
    for (const char *p : paths) {
        if (fileExists(p)) {
            LOGI("Magisk detected at: %s", p);
            return true;
        }
    }
    return false;
}

// Burp Suite detect (app folder check)
bool detectBurpSuite() {
    return fileExists("/data/data/com.portswigger.burp");
}

// HTTP Canary detect (app folder check)
bool detectCanary() {
    return fileExists("/data/data/com.guoshi.httpcanary");
}

// MITM Proxy detect (ports 8080 or 8888 on localhost in /proc/net/tcp)
bool detectMITM() {
    std::ifstream tcpFile("/proc/net/tcp");
    std::string line;
    while (std::getline(tcpFile, line)) {
        if (line.find("0100007F") != std::string::npos) { // 127.0.0.1 in hex
            if (line.find("1F90") != std::string::npos || line.find("22B8") != std::string::npos) { // ports 8080 or 8888 in hex
                LOGI("MITM proxy detected on port 8080 or 8888");
                return true;
            }
        }
    }
    return false;
}

// Proxy env var detect
bool detectProxy() {
    const char *envVars[] = {"http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"};
    for (auto envVar : envVars) {
        const char *val = getenv(envVar);
        if (val && strstr(val, "127.0.0.1")) {
            LOGI("Proxy environment variable detected: %s = %s", envVar, val);
            return true;
        }
    }
    return false;
}
