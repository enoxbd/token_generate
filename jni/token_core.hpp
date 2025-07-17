#ifndef TOKEN_CORE_HPP
#define TOKEN_CORE_HPP

#include <jni.h>
#include <string>

std::string generateSecureToken(JNIEnv *env, jobject context, const std::string &sessionId);

// sha256 & aesEncrypt এর declaration যদি আলাদা ফাইলে থাকে তাহলে include করো

#endif
