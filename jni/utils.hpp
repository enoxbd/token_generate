#ifndef UTILS_HPP
#define UTILS_HPP

#include <jni.h>
#include <string>

std::string getSharedPreference(JNIEnv* env, jobject context, const std::string& key);

#endif // UTILS_HPP
