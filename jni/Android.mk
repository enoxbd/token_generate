LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

# Your native library name is enoxbd (libenoxbd.so)
LOCAL_MODULE := enoxbd

# Your C++ source file(s)
LOCAL_SRC_FILES := SecureTokenGenerator.cpp

# OpenSSL headers path — adjust this to your environment
LOCAL_C_INCLUDES := $(LOCAL_PATH)/openssl/include

# Link OpenSSL static libcrypto.a per architecture
ifeq ($(TARGET_ARCH_ABI), armeabi-v7a)
    LOCAL_STATIC_LIBRARIES := libcrypto_armv7a
endif

ifeq ($(TARGET_ARCH_ABI), arm64-v8a)
    LOCAL_STATIC_LIBRARIES := libcrypto_arm64
endif

# Enable C++11
LOCAL_CPPFLAGS := -std=c++11

# Link with Android logging library
LOCAL_LDLIBS := -llog

# Strip symbols in release build to make reverse engineering harder
LOCAL_STRIP := true

# Explicit output filename (optional, but makes sure the name is libenoxbd.so)
LOCAL_MODULE_FILENAME := enoxbd

# Enable exceptions and RTTI if you need
LOCAL_CPP_FEATURES := exceptions rtti

include $(BUILD_SHARED_LIBRARY)

# OpenSSL static libs definitions

# armeabi-v7a libcrypto
include $(CLEAR_VARS)
LOCAL_MODULE := libcrypto_armv7a
LOCAL_SRC_FILES := openssl/libs/armeabi-v7a/libcrypto.a
include $(PREBUILT_STATIC_LIBRARY)

# arm64-v8a libcrypto
include $(CLEAR_VARS)
LOCAL_MODULE := libcrypto_arm64
LOCAL_SRC_FILES := openssl/libs/arm64-v8a/libcrypto.a
include $(PREBUILT_STATIC_LIBRARY)
