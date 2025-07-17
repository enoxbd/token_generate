#ifndef UTILS_HPP
#define UTILS_HPP

#include <jni.h>
#include <string>

std::string getSharedPreference(JNIEnv *env, jobject context, const std::string &key);
std::string getDeviceId(JNIEnv *env, jobject context);
std::string getDeviceFingerprint(JNIEnv *env);
std::string getCurrentTime();
std::string generateRandomString(int length);
std::string sha256(const std::string &input);
std::string aesEncrypt(const std::string &data, const std::string &password);

#endif // UTILS_HPP
