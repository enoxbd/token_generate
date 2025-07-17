LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := tokenlib
LOCAL_SRC_FILES := \
    main.cpp \
    token_core.cpp \
    utils.cpp

LOCAL_C_INCLUDES := $(LOCAL_PATH)

LOCAL_CPPFLAGS := -std=c++11 -fexceptions
LOCAL_LDLIBS := -llog

include $(BUILD_SHARED_LIBRARY)
