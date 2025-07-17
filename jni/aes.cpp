#include "aes.hpp"

// AES S-box
const uint8_t AES128::sbox[256] = {
    // 256 values here...
    // For brevity, I'll only include the first few values here. Full sbox needed in actual code.
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    // ... continue for all 256 bytes
    // (You can find full AES S-box online easily)
};

AES128::AES128(const uint8_t* key) {
    KeyExpansion(key);
}

void AES128::KeyExpansion(const uint8_t* key) {
    // Key expansion code here (176 bytes)
    // ...
}

void AES128::AddRoundKey(uint8_t* state, int round) {
    // AddRoundKey implementation
}

void AES128::SubBytes(uint8_t* state) {
    // SubBytes implementation
}

void AES128::ShiftRows(uint8_t* state) {
    // ShiftRows implementation
}

void AES128::MixColumns(uint8_t* state) {
    // MixColumns implementation
}

uint8_t AES128::xtime(uint8_t x) {
    return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
}

void AES128::Cipher(uint8_t* input, uint8_t* output) {
    // AES encrypt block implementation
}

void AES128::Encrypt(const uint8_t* input, uint8_t* output) {
    Cipher(const_cast<uint8_t*>(input), output);
}

// ECB encrypt helper (pads to 16 bytes)
std::string AES128::EncryptECB(const std::string& plaintext) {
    size_t len = plaintext.size();
    size_t paddedLen = ((len + 15) / 16) * 16;
    std::string padded = plaintext;
    padded.resize(paddedLen, 0);

    std::string ciphertext(paddedLen, '\0');

    for (size_t i = 0; i < paddedLen; i += 16) {
        Encrypt((const uint8_t*)padded.data() + i, (uint8_t*)&ciphertext[i]);
    }
    return ciphertext;
}
