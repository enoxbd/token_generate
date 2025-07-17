#ifndef JNI_UTILS_HPP
#define JNI_UTILS_HPP

#include <jni.h>
#include <string>

namespace jniutils {

    // Helper: Get string from SharedPreferences by key
    std::string getSharedPreferenceString(JNIEnv* env,
                                          jobject context,
                                          const std::string& prefName,
                                          const std::string& key);

    // Helper: Get Android ID
    std::string getAndroidID(JNIEnv* env, jobject context);

    // Helper: Get Build.FINGERPRINT string
    std::string getBuildFingerprint(JNIEnv* env);

    // Helper: Get device hardware info (MODEL + MANUFACTURER)
    std::string getDeviceHardwareInfo(JNIEnv* env);

}

#endif // JNI_UTILS_HPP
