#include "TokenCore.hpp"
#include "sha256_small.hpp"
#include "utils.hpp"
#include <ctime>
#include <sstream>
#include <iomanip>
#include <openssl/aes.h>
#include <openssl/evp.h>

const std::string ENCRYPTION_KEY = "enoxbdmontasir12";

std::string encryptAES(const std::string& plaintext, const std::string& password) {
    unsigned char key[32] = {0};
    unsigned char iv[16] = {0};
    memcpy(key, password.c_str(), std::min(password.size(), sizeof(key)));

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    std::string ciphertext;
    int len;
    unsigned char outbuf[1024];

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, outbuf, &len, (const unsigned char*)plaintext.c_str(), plaintext.length());
    ciphertext = std::string((char*)outbuf, len);

    EVP_EncryptFinal_ex(ctx, outbuf, &len);
    ciphertext += std::string((char*)outbuf, len);

    EVP_CIPHER_CTX_free(ctx);
    return toHex(ciphertext);  // encode as hex
}

std::string generateSecureToken(const std::string& sessionId, const std::string& deviceId) {
    std::string timestamp = std::to_string(std::time(nullptr));
    std::string randomKey = generateRandomString(16);
    std::string raw = sessionId + "|" + deviceId + "|" + timestamp + "|" + randomKey;
    std::string hash = sha256(raw);
    return encryptAES(hash, ENCRYPTION_KEY);
}
