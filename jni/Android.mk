LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := enoxbd

LOCAL_SRC_FILES := \
    main.cpp \
    security_core.cpp \
    token_core.cpp \
    utils.cpp \
    sha256_small.cpp \
    aes.cpp   # এখানেই aes_core.cpp এর জায়গায় aes.cpp দিবে

LOCAL_CPPFLAGS += -std=c++11

LOCAL_LDLIBS := -llog -landroid

include $(BUILD_SHARED_LIBRARY)
