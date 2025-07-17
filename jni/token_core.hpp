// token_core.hpp
#ifndef TOKEN_CORE_HPP
#define TOKEN_CORE_HPP

#include <string>
std::string generateSecureToken(const std::string& session_id, const std::string& device_id);

#endif // TOKEN_CORE_HPP
