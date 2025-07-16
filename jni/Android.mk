LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := securetoken
LOCAL_SRC_FILES := securetoken.cpp
LOCAL_LDLIBS    := -llog -lcrypto
include $(BUILD_SHARED_LIBRARY)