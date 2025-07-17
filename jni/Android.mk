LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := enoxbd

LOCAL_SRC_FILES := \
    main.cpp \
    TokenCore.cpp \
    utils.cpp

LOCAL_C_INCLUDES := $(LOCAL_PATH)

LOCAL_CPPFLAGS += -std=c++11 -fexceptions -frtti
LOCAL_LDLIBS := -llog -lssl -lcrypto

include $(BUILD_SHARED_LIBRARY)
