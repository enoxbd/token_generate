#ifndef AES_ENCRYPTION_HPP
#define AES_ENCRYPTION_HPP

#include <string>
#include <vector>
#include <stdint.h>

class AES128 {
private:
    static const uint8_t sbox[256];
    static const uint8_t rcon[10];

    uint8_t key[16];
    uint8_t roundKeys[176];

    void KeyExpansion();
    void SubBytes(uint8_t* state);
    void ShiftRows(uint8_t* state);
    void MixColumns(uint8_t* state);
    void AddRoundKey(uint8_t* state, int round);
    void Cipher(uint8_t* input, uint8_t* output);

public:
    AES128(const std::string& keyStr);
    std::string encrypt(const std::string& plaintext);
};

#endif // AES_ENCRYPTION_HPP
