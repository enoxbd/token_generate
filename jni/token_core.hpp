#ifndef TOKEN_CORE_HPP
#define TOKEN_CORE_HPP

#include <string>

// এই ফাংশন টোকেন তৈরি করবে, session_id ইনপুট নিবে
std::string generateSecureToken(const std::string& session_id);

#endif
