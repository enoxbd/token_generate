#ifndef TOKEN_CORE_HPP
#define TOKEN_CORE_HPP

#include <string>

std::string generateSecureToken(const std::string& sessionId, const std::string& deviceId);

#endif
