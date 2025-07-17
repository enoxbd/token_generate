#ifndef UTILS_HPP
#define UTILS_HPP

#include <jni.h>
#include <string>

// SharedPreferences থেকে session_id নেবে
std::string getSharedPreference(JNIEnv *env, jobject context, const std::string &key);

// ডিভাইসের Android ID নিবে
std::string getDeviceId(JNIEnv *env, jobject context);

// ডিভাইসের fingerprint নিবে
std::string getDeviceFingerprint(JNIEnv *env);

// বর্তমান সময় স্ট্রিং আকারে নিবে
std::string getCurrentTime();

// দৈর্ঘ্য অনুযায়ী র‍্যান্ডম স্ট্রিং তৈরি করবে
std::string generateRandomString(int length);

#endif
