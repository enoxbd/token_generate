LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := secure_native
LOCAL_SRC_FILES := main.cpp token_core.cpp sequrty_core.cpp

LOCAL_C_INCLUDES := $(LOCAL_PATH)  # header ফাইলের জন্য

LOCAL_LDLIBS := -llog -lcrypto

include $(BUILD_SHARED_LIBRARY)
