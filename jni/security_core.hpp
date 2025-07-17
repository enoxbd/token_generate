#ifndef SECURITY_CORE_HPP
#define SECURITY_CORE_HPP

#include <jni.h>
#include <string>

// কোন extern "C" নাই কারণ std::string রিটার্ন করছে

std::string detectThreats(JNIEnv* env, jobject ctx);

#endif
