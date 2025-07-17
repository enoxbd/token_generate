#include "utils.hpp"
#include <jni.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <cstdlib>
#include <android/log.h>
#include <sys/system_properties.h>

#define LOG_TAG "Utils"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// SHA256 function from your own sha256_small.hpp
std::string sha256(const std::string& input); // Make sure you have the declaration somewhere

std::string getSystemProperty(const char* key) {
    char value[PROP_VALUE_MAX];
    __system_property_get(key, value);
    return std::string(value);
}

std::string getCurrentTimeMillis() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    long long millis = ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
    return std::to_string(millis);
}

std::string generateRandomHex(size_t length) {
    const char* hex_chars = "0123456789abcdef";
    std::stringstream ss;
    srand(time(NULL));
    for (size_t i = 0; i < length; ++i) {
        ss << hex_chars[rand() % 16];
    }
    return ss.str();
}

std::string bytesToHex(const std::vector<unsigned char>& bytes) {
    std::stringstream ss;
    for (auto byte : bytes) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return ss.str();
}
