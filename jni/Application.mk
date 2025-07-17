APP_ABI := armeabi-v7a arm64-v8a
APP_PLATFORM := android-21

APP_STL := c++_static
APP_CPPFLAGS := -std=c++11
APP_OPTIM := release

# To enable exceptions and RTTI (if needed)
APP_CPPFLAGS += -frtti -fexceptions
