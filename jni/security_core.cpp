#include "security_core.hpp"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <android/log.h>

#define LOG_TAG "SecurityCore"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

bool detectRoot() {
    return access("/system/xbin/su", F_OK) == 0 || access("/system/bin/su", F_OK) == 0;
}

bool detectFrida() {
    return access("/proc/frida", F_OK) == 0;
}

bool detectMagisk() {
    return access("/sbin/.magisk", F_OK) == 0 || access("/data/adb/magisk", F_OK) == 0;
}

bool detectBurpSuite() {
    return access("/data/data/burp", F_OK) == 0;
}

bool detectNetworkProxy() {
    const char* http_proxy = getenv("http_proxy");
    const char* https_proxy = getenv("https_proxy");
    const char* all_proxy = getenv("all_proxy");

    if (http_proxy && strstr(http_proxy, "127.0.0.1")) return true;
    if (https_proxy && strstr(https_proxy, "127.0.0.1")) return true;
    if (all_proxy && strstr(all_proxy, "127.0.0.1")) return true;

    return false;
}

bool detectMITM() {
    return detectNetworkProxy();
}

// App mod detection disabled (excluded)

bool isThreatDetected() {
    if (detectRoot()) {
        LOGI("Threat Detected: Root");
        return true;
    }
    if (detectFrida()) {
        LOGI("Threat Detected: Frida");
        return true;
    }
    if (detectMagisk()) {
        LOGI("Threat Detected: Magisk");
        return true;
    }
    if (detectBurpSuite()) {
        LOGI("Threat Detected: Burp Suite");
        return true;
    }
    if (detectMITM()) {
        LOGI("Threat Detected: Network Proxy (127.0.0.1)");
        return true;
    }
    return false;
}
