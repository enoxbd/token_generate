#include "utils.hpp"
#include <sys/system_properties.h>

std::string getprop(const char* key) {
    char buf[PROP_VALUE_MAX];
    __system_property_get(key, buf);
    return std::string(buf);
}
