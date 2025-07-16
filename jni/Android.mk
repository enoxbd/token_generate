LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := secure_native
LOCAL_SRC_FILES := main.cpp security_core.cpp token_core.cpp

LOCAL_C_INCLUDES := $(LOCAL_PATH)

LOCAL_LDLIBS := -llog

include $(BUILD_SHARED_LIBRARY)
