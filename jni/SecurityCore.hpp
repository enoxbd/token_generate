#ifndef SECURITY_CORE_HPP
#define SECURITY_CORE_HPP

#include <jni.h>
#include <string>

namespace securitycore {

// Initialize security core with app package name and Android Context object
void initialize(JNIEnv* env, jobject context, const std::string& packageName);

// Checks all threats and returns true if environment is clean
bool isEnvironmentSecure(JNIEnv* env, jobject context);

// Exit app immediately if threat detected
void exitApp(JNIEnv* env);

// Root detection methods
bool detectRoot(JNIEnv* env);

// Debugger detection methods
bool detectDebugger();

// Frida detection methods
bool detectFrida();

// Magisk detection methods
bool detectMagisk();

// API capture detection methods
bool detectApiCapture(JNIEnv* env);

// VPN detection methods
bool detectVpn(JNIEnv* env);

// Utility to check if suspicious files exist
bool checkForSuspiciousFiles(const std::string& path);

} // namespace securitycore

#endif // SECURITY_CORE_HPP
