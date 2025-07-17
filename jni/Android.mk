LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := enoxbd

LOCAL_SRC_FILES := \
    main.cpp \
    JNIUtils.cpp \
    SecurityCore.cpp \
    TokenCore.cpp \
    aes.c \
    sha256_small.cpp

LOCAL_CPPFLAGS += -std=c++11
LOCAL_LDLIBS := -llog

include $(BUILD_SHARED_LIBRARY)
