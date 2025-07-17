#ifndef SECURITY_CORE_HPP
#define SECURITY_CORE_HPP

#include <jni.h>
#include <string>

bool detectRoot();
bool detectFrida();
bool detectMagisk();
bool detectBurpSuite();
bool detectCanary();
bool detectMITM();
bool detectProxy();
bool detectAppMod();

#endif
