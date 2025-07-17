LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := secure_native
LOCAL_SRC_FILES := \
    token_core.cpp \
    security_core.cpp \
    utils.cpp \
    main.cpp

LOCAL_CPPFLAGS += -std=c++11 -fexceptions
LOCAL_LDLIBS := -llog

include $(BUILD_SHARED_LIBRARY)
