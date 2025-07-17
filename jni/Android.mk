LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := securitylib

LOCAL_SRC_FILES := \
    SecurityCore.cpp \
    TokenCore.cpp \
    JNIUtils.cpp

LOCAL_C_INCLUDES := $(LOCAL_PATH)/include

LOCAL_CPPFLAGS := -std=c++11 -Wall -Wextra -fPIE -fPIC

LOCAL_LDLIBS := -llog

include $(BUILD_SHARED_LIBRARY)
