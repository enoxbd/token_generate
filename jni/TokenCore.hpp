#ifndef TOKEN_CORE_HPP
#define TOKEN_CORE_HPP

#include <jni.h>
#include <string>

namespace tokencore {

// Generate secure token reading session id from SharedPreferences with given key
std::string generateSecureToken(JNIEnv* env, jobject context, const std::string& sessionKey);

}

#endif // TOKEN_CORE_HPP
