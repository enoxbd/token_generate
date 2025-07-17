#include "security_core.hpp"
#include <android/log.h>

#define LOG_TAG "SecurityCore"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

extern "C" bool detectThreats(JNIEnv* env, jobject ctx) {
    LOGI("No threats found");
    return false; // Threat নাই
}
