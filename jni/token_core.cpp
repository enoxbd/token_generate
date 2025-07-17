#include "token_core.hpp"
#include "utils.hpp"
#include "sha256_small.hpp"
#include "aes.hpp"

std::string generateSecureToken(const std::string& session_id) {
    std::string deviceId = getDeviceId();
    std::string fingerprint = getDeviceFingerprint();
    std::string currentTime = getCurrentTime();
    std::string randomStr = generateRandomString(16);

    // ডাটা গুলো একসাথে concatenate করলাম
    std::string rawToken = session_id + "|" + deviceId + "|" + currentTime + "|" + fingerprint + "|" + randomStr;

    // SHA256 হ্যাশ
    std::string hashedToken = sha256(rawToken);

    // AES দিয়ে এনক্রিপ্ট
    std::string encryptedToken = aesEncrypt(hashedToken, "enoxbdmontasir12");

    return encryptedToken;
}
