#include <jni.h>
#include "token_core.hpp"  // generateSecureToken() ডিক্লারেশন

extern "C"
JNIEXPORT jstring JNICALL
Java_com_my_newproject8_SecureManager_getSecureToken(JNIEnv* env, jobject thiz, jobject context) {
    std::string token = generateSecureToken(env, context);
    return env->NewStringUTF(token.c_str());
}
