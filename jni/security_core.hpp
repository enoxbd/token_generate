#ifndef SECURITY_CORE_HPP
#define SECURITY_CORE_HPP

#include <jni.h>
#include <string>

#ifdef __cplusplus
extern "C" {
#endif

// এখন detectThreats std::string রিটার্ন করবে
std::string detectThreats(JNIEnv* env, jobject ctx);

#ifdef __cplusplus
}
#endif

#endif
