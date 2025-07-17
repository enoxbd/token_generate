#ifndef UTILS_HPP
#define UTILS_HPP

#include <jni.h>
#include <string>

// SharedPreferences থেকে session_id নেবে
std::string getSharedPreference(JNIEnv *env, jobject context, const std::string &key);

// Android ID নিবে
std::string getDeviceId(JNIEnv *env, jobject context);

// Build fingerprint নিবে
std::string getDeviceFingerprint(JNIEnv *env);

// বর্তমান সময়
std::string getCurrentTime();

// দৈর্ঘ্য অনুযায়ী র‍্যান্ডম স্ট্রিং
std::string generateRandomString(int length);

#endif
