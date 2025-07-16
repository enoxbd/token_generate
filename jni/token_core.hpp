#ifndef TOKEN_CORE_HPP
#define TOKEN_CORE_HPP

#include <jni.h>
#include <string>

std::string generateSecureToken(JNIEnv* env, jobject ctx);

#endif
