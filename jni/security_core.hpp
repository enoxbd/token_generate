#ifndef SECURITY_CORE_HPP
#define SECURITY_CORE_HPP

#include <jni.h>

// সব ধরনের থ্রেট ডিটেকশন পরিচালনার ফাংশন
bool isDeviceCompromised(JNIEnv *env, jobject context);

// রুট ডিটেকশন
bool isDeviceRooted();

// ম্যাজিক ফাইল/পাথ চেক করে Magisk ডিটেকশন
bool isMagiskPresent();

// ডিবাগার সংযুক্ত কিনা চেক করে
bool isDebuggerAttached();

// ফ্রিডা ডিটেকশন (pipe /frida/)
bool isFridaDetected();

// Burp Suite, HTTP Canary, MITMProxy ডিটেকশন (127.0.0.1 proxy ইত্যাদি)
bool isProxyDetected(JNIEnv *env);

// প্যাকেজ নাম যাচাই করে
bool isCorrectPackage(JNIEnv *env, jobject context, const char *expectedPackage);

// কোনো থ্রেট পাওয়া গেলে অ্যাপ এক্সিট করায়
void forceExit();
#endif
