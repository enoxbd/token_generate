#include "token_core.hpp"
#include "utils.hpp"

std::string generateSecureToken(JNIEnv *env, jobject context, const std::string &sessionId) {
    std::string deviceId = getDeviceId(env, context);
    std::string fingerprint = getDeviceFingerprint(env);
    std::string currentTime = getCurrentTime();
    std::string randomStr = generateRandomString(16);

    std::string rawToken = sessionId + deviceId + fingerprint + currentTime + randomStr;

    std::string hashedToken = sha256(rawToken);
    std::string encryptedToken = aesEncrypt(hashedToken, "enoxbdmontasir12");

    return encryptedToken;
}
