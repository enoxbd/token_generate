#include "security_core.hpp"
#include <unistd.h>
#include <sys/stat.h>
#include <fstream>
#include <dlfcn.h>
#include <android/log.h>
#include <cstdlib>
#include <cstring>
#include <string>

#define LOG_TAG "SecurityCore"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

static void exitApp() {
    LOGI("Security threat detected! Exiting...");
    _exit(0);
}

static bool fileExists(const char *path) {
    return access(path, F_OK) == 0;
}

bool detectRoot() {
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
    for (const char *p : paths) {
        if (fileExists(p)) {
            LOGI("Root detected at: %s", p);
            return true;
        }
    }
    return false;
}

bool detectFrida() {
    void *handle = dlopen("libfrida-gadget.so", RTLD_LAZY);
    if (handle) {
        dlclose(handle);
        LOGI("Frida gadget library detected!");
        return true;
    }
    return false;
}

bool detectMagisk() {
    const char *paths[] = {
        "/sbin/magisk",
        "/init.magisk.rc",
        "/system/bin/magisk",
        "/data/adb/magisk.img",
        "/data/adb/magisk",
    };
    for (const char *p : paths) {
        if (fileExists(p)) {
            LOGI("Magisk detected at: %s", p);
            return true;
        }
    }
    return false;
}

bool detectBurpSuite() {
    // Burp সুনির্দিষ্ট পাথ চেক কর
    return fileExists("/data/data/com.portswigger.burp");
}

bool detectCanary() {
    return fileExists("/data/data/com.guoshi.httpcanary");
}

bool detectMITM() {
    // /proc/net/tcp থেকে loopback এ 8080/8888 পোর্ট চেক করা যাবে
    std::ifstream tcpFile("/proc/net/tcp");
    std::string line;
    while (std::getline(tcpFile, line)) {
        if (line.find("0100007F") != std::string::npos) { // 127.0.0.1
            if (line.find("1F90") != std::string::npos || line.find("22B8") != std::string::npos) { // 8080 or 8888 hex
                LOGI("MITM proxy port detected in /proc/net/tcp");
                return true;
            }
        }
    }
    return false;
}

bool detectProxy() {
    const char *envs[] = { "http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY" };
    for (const char *env : envs) {
        const char *val = getenv(env);
        if (val && strstr(val, "127.0.0.1")) {
            LOGI("Proxy detected via env var: %s", val);
            return true;
        }
    }
    return false;
}

bool detectAppMod() {
    // লাকি প্যাচার বা অন্য মড টুলস চেক করতে পারো এখানে (যেমন path, package)
    // তুমি বললে বাদ দিবো
    return false;
}
