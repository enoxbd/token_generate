#ifndef SECURITY_CORE_HPP
#define SECURITY_CORE_HPP

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

bool detectThreats(JNIEnv* env, jobject ctx);

#ifdef __cplusplus
}
#endif

#endif
