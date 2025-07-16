LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := securetoken
LOCAL_SRC_FILES := securetoken.cpp

# শুধু log লাইব দিয়ে রাখি
LOCAL_LDLIBS    := -llog

include $(BUILD_SHARED_LIBRARY)
