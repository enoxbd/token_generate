// SecureTokenGenerator.cpp

#include <jni.h>
#include <string>
#include <ctime>
#include <cstring>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <android/log.h>

#define LOG_TAG "SecureTokenGenerator"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Fixed secret key for AES-256-CBC encryption (32 bytes key for AES-256).
// The given key "enoxbdmontasir12" is 16 bytes - so we must extend it or hash it to 32 bytes.
// Here we simply hash it with SHA256 to get 32 bytes.
static const char* AES_SECRET_KEY_RAW = "enoxbdmontasir12";

// AES block size and key size
constexpr int AES_KEY_LENGTH = 32;     // 256 bits
constexpr int AES_IV_LENGTH = 16;      // AES block size is 16 bytes

// Length of the random key string to generate
constexpr int RANDOM_KEY_LENGTH = 12;

// Base64 encode function using OpenSSL BIO
static std::string base64Encode(const unsigned char* buffer, size_t length) {
    BIO* bio = nullptr;
    BIO* b64 = nullptr;
    BUF_MEM* bufferPtr = nullptr;

    b64 = BIO_new(BIO_f_base64());
    if (!b64) return "";

    // Do not use newlines to flush buffer (important for token encoding)
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        BIO_free_all(b64);
        return "";
    }

    bio = BIO_push(b64, bio);

    // Write data
    if (BIO_write(bio, buffer, (int)length) <= 0) {
        BIO_free_all(bio);
        return "";
    }

    if (BIO_flush(bio) != 1) {
        BIO_free_all(bio);
        return "";
    }

    BIO_get_mem_ptr(bio, &bufferPtr);
    if (!bufferPtr) {
        BIO_free_all(bio);
        return "";
    }

    std::string encoded(bufferPtr->data, bufferPtr->length);

    BIO_free_all(bio);
    return encoded;
}

// Generate cryptographically secure random alphanumeric string of length len
static std::string generateRandomKey(int len) {
    const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    const size_t charsetSize = sizeof(charset) - 1;
    unsigned char randomBytes[len];

    if (RAND_bytes(randomBytes, len) != 1) {
        // Random generation failed
        return "";
    }

    std::string randomKey;
    randomKey.reserve(len);
    for (int i = 0; i < len; i++) {
        randomKey += charset[randomBytes[i] % charsetSize];
    }
    return randomKey;
}

// Convert jstring to std::string
static std::string jstringToStdString(JNIEnv* env, jstring jStr) {
    if (!jStr) return "";

    const char* chars = env->GetStringUTFChars(jStr, nullptr);
    if (!chars) return "";

    std::string ret(chars);
    env->ReleaseStringUTFChars(jStr, chars);
    return ret;
}

// Derive 256-bit AES key from the raw password string using SHA256
static bool deriveAESKey(const std::string& password, unsigned char* outKey32Bytes) {
    if (!outKey32Bytes) return false;
    unsigned char hash[SHA256_DIGEST_LENGTH];

    if (!SHA256(reinterpret_cast<const unsigned char*>(password.c_str()), password.size(), hash)) {
        return false;
    }
    memcpy(outKey32Bytes, hash, AES_KEY_LENGTH);
    return true;
}

// AES-256-CBC encrypt input data, output buffer allocated by caller
// Output = IV(16 bytes) + ciphertext
// Return size of output buffer on success, -1 on failure
static int aes256cbcEncrypt(
    const unsigned char* plaintext, int plaintext_len,
    const unsigned char* key,
    unsigned char* outBuffer /* must have at least IV + ciphertext size */
) {
    unsigned char iv[AES_IV_LENGTH];

    // Generate random IV
    if (RAND_bytes(iv, AES_IV_LENGTH) != 1) {
        LOGE("RAND_bytes for IV failed");
        return -1;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LOGE("EVP_CIPHER_CTX_new failed");
        return -1;
    }

    int len = 0;
    int ciphertext_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        LOGE("EVP_EncryptInit_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Enable padding (PKCS#7) by default

    // Place IV at beginning of output buffer
    memcpy(outBuffer, iv, AES_IV_LENGTH);

    if (EVP_EncryptUpdate(ctx, outBuffer + AES_IV_LENGTH, &len, plaintext, plaintext_len) != 1) {
        LOGE("EVP_EncryptUpdate failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, outBuffer + AES_IV_LENGTH + len, &len) != 1) {
        LOGE("EVP_EncryptFinal_ex failed");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    // Return total length = IV + ciphertext
    return AES_IV_LENGTH + ciphertext_len;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_my_newproject8_SecureManager_generateSecureToken(JNIEnv* env, jobject /* this */, jstring j_session_id) {
    if (j_session_id == nullptr) {
        LOGE("session_id is null");
        return nullptr;
    }

    // Step 1: Convert jstring session_id to std::string
    std::string session_id = jstringToStdString(env, j_session_id);
    if (session_id.empty()) {
        LOGE("session_id conversion failed or empty");
        return nullptr;
    }

    // Step 2: Get device_id
    // Since device_id fetching inside native code is complex and usually requires Java,
    // here we mock device_id as a constant string for demo.
    // You can extend this by passing device_id as parameter from Java if needed.
    const std::string device_id = "DEVICEID1234567890";

    // Step 3: Get current UNIX timestamp (seconds)
    std::time_t timestamp = std::time(nullptr);

    // Step 4: Generate 12-char cryptographically secure random key
    std::string random_key = generateRandomKey(RANDOM_KEY_LENGTH);
    if (random_key.empty()) {
        LOGE("Random key generation failed");
        return nullptr;
    }

    // Step 5: Concatenate all fields with colon separator:
    // "session_id:device_id:timestamp:random_key"
    std::string concat_str = session_id + ":" + device_id + ":" + std::to_string(timestamp) + ":" + random_key;

    // Step 6: SHA256 hash the concatenated string
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    if (!SHA256(reinterpret_cast<const unsigned char*>(concat_str.c_str()), concat_str.length(), sha256_hash)) {
        LOGE("SHA256 hashing failed");
        return nullptr;
    }

    // Step 7: Derive AES-256 key from secret key string by SHA256 hashing
    unsigned char aes_key[AES_KEY_LENGTH];
    if (!deriveAESKey(AES_SECRET_KEY_RAW, aes_key)) {
        LOGE("AES key derivation failed");
        return nullptr;
    }

    // Step 8: Encrypt the SHA256 hash using AES-256-CBC
    // Output buffer size: IV(16) + ciphertext (SHA256_DIGEST_LENGTH + AES block size padding)
    int max_out_len = AES_IV_LENGTH + SHA256_DIGEST_LENGTH + AES_IV_LENGTH; // safe upper bound
    unsigned char* encrypted_output = new unsigned char[max_out_len];
    if (!encrypted_output) {
        LOGE("Failed to allocate memory for encrypted output");
        return nullptr;
    }

    int encrypted_len = aes256cbcEncrypt(sha256_hash, SHA256_DIGEST_LENGTH, aes_key, encrypted_output);
    if (encrypted_len <= 0) {
        LOGE("AES encryption failed");
        delete[] encrypted_output;
        return nullptr;
    }

    // Step 9: Base64 encode the IV + ciphertext
    std::string base64_encoded = base64Encode(encrypted_output, (size_t)encrypted_len);

    delete[] encrypted_output;

    if (base64_encoded.empty()) {
        LOGE("Base64 encoding failed");
        return nullptr;
    }

    // Step 10: Return as jstring
    return env->NewStringUTF(base64_encoded.c_str());
}
