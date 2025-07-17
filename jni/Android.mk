LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := secure_native
LOCAL_SRC_FILES := \
    token_core.cpp \
    sha256_small.cpp \
    security_core.cpp \
    main.cpp \
    utils.cpp

LOCAL_CPPFLAGS += -std=c++11

include $(BUILD_SHARED_LIBRARY)
