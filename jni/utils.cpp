#include "utils.hpp"
#include <jni.h>
#include <string>
#include <android/log.h>
#include <ctime>
#include <cstdlib>
#include <sstream>
#include <iomanip>
#include <random>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define LOG_TAG "Utils"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// SharedPreferences থেকে key দিয়ে value নেয়ার JNI কোড
std::string getSharedPreference(JNIEnv *env, jobject context, const std::string &key) {
    jclass contextClass = env->GetObjectClass(context);
    jmethodID getSharedPrefMethod = env->GetMethodID(contextClass, "getSharedPreferences", "(Ljava/lang/String;I)Landroid/content/SharedPreferences;");
    jstring spName = env->NewStringUTF("YourPreferenceName"); // স্পিফিক SharedPreferences নাম
    jobject sharedPreferences = env->CallObjectMethod(context, getSharedPrefMethod, spName, 0);

    jclass spClass = env->GetObjectClass(sharedPreferences);
    jmethodID getStringMethod = env->GetMethodID(spClass, "getString", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;");
    jstring jKey = env->NewStringUTF(key.c_str());
    jstring jDefault = env->NewStringUTF("");

    jstring jValue = (jstring)env->CallObjectMethod(sharedPreferences, getStringMethod, jKey, jDefault);

    const char *valueChars = env->GetStringUTFChars(jValue, NULL);
    std::string valueStr(valueChars);
    env->ReleaseStringUTFChars(jValue, valueChars);

    env->DeleteLocalRef(jKey);
    env->DeleteLocalRef(jDefault);
    env->DeleteLocalRef(jValue);
    env->DeleteLocalRef(spName);
    env->DeleteLocalRef(sharedPreferences);
    env->DeleteLocalRef(spClass);
    env->DeleteLocalRef(contextClass);

    return valueStr;
}

// Device ID নেয়ার JNI কোড (Android ID)
std::string getDeviceId(JNIEnv *env, jobject context) {
    jclass contextClass = env->GetObjectClass(context);
    jmethodID getContentResolverMethod = env->GetMethodID(contextClass, "getContentResolver", "()Landroid/content/ContentResolver;");
    jobject contentResolver = env->CallObjectMethod(context, getContentResolverMethod);

    jclass secureClass = env->FindClass("android/provider/Settings$Secure");
    jmethodID getStringMethod = env->GetStaticMethodID(secureClass, "getString",
                                                      "(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;");
    jstring androidIdStr = env->NewStringUTF("android_id");
    jstring androidId = (jstring)env->CallStaticObjectMethod(secureClass, getStringMethod, contentResolver, androidIdStr);

    const char *androidIdChars = env->GetStringUTFChars(androidId, NULL);
    std::string androidIdStrCpp(androidIdChars);
    env->ReleaseStringUTFChars(androidId, androidIdChars);

    env->DeleteLocalRef(androidIdStr);
    env->DeleteLocalRef(androidId);
    env->DeleteLocalRef(secureClass);
    env->DeleteLocalRef(contentResolver);
    env->DeleteLocalRef(contextClass);

    return androidIdStrCpp;
}

// Device fingerprint নেয়ার JNI কোড (Build.FINGERPRINT)
std::string getDeviceFingerprint(JNIEnv *env) {
    jclass buildClass = env->FindClass("android/os/Build");
    jfieldID fingerprintField = env->GetStaticFieldID(buildClass, "FINGERPRINT", "Ljava/lang/String;");
    jstring fingerprint = (jstring)env->GetStaticObjectField(buildClass, fingerprintField);

    const char *fpChars = env->GetStringUTFChars(fingerprint, NULL);
    std::string fingerprintStr(fpChars);
    env->ReleaseStringUTFChars(fingerprint, fpChars);

    env->DeleteLocalRef(fingerprint);
    env->DeleteLocalRef(buildClass);

    return fingerprintStr;
}

// Current time string (epoch seconds)
std::string getCurrentTime() {
    std::time_t now = std::time(nullptr);
    return std::to_string(now);
}

// Random string generator (hexadecimal)
std::string generateRandomString(int length) {
    const char *chars = "0123456789abcdef";
    std::string result;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);

    for (int i = 0; i < length; ++i) {
        result += chars[dis(gen)];
    }
    return result;
}

// SHA256 hash function (using OpenSSL)
std::string sha256(const std::string &input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256Ctx;
    SHA256_Init(&sha256Ctx);
    SHA256_Update(&sha256Ctx, input.c_str(), input.size());
    SHA256_Final(hash, &sha256Ctx);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// AES-128 CBC encrypt (using OpenSSL)
std::string aesEncrypt(const std::string &data, const std::string &password) {
    // AES key must be 16 bytes for AES-128
    unsigned char key[16] = {0};
    // Simple key derivation: copy password or pad with 0
    for (int i = 0; i < 16 && i < (int)password.size(); i++) {
        key[i] = password[i];
    }

    unsigned char iv[16] = {0};  // zero IV

    AES_KEY aesKey;
    AES_set_encrypt_key(key, 128, &aesKey);

    // Padding data to multiple of 16 bytes (PKCS7)
    size_t dataLen = data.size();
    size_t paddedLen = ((dataLen / 16) + 1) * 16;
    unsigned char *inputBuf = new unsigned char[paddedLen];
    memcpy(inputBuf, data.c_str(), dataLen);
    unsigned char padVal = paddedLen - dataLen;
    for (size_t i = dataLen; i < paddedLen; i++) {
        inputBuf[i] = padVal;
    }

    unsigned char *outBuf = new unsigned char[paddedLen];

    AES_cbc_encrypt(inputBuf, outBuf, paddedLen, &aesKey, iv, AES_ENCRYPT);

    // Convert to hex string
    std::stringstream ss;
    for (size_t i = 0; i < paddedLen; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)outBuf[i];
    }

    delete[] inputBuf;
    delete[] outBuf;

    return ss.str();
}
