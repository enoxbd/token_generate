#ifndef AES_HPP
#define AES_HPP

#include <string>
#include <vector>
#include <cstring>
#include <stdint.h>

class AES {
public:
    AES(const std::string& key);
    std::string encrypt(const std::string& plaintext);
    std::string decrypt(const std::string& ciphertext);

private:
    void keyExpansion(const uint8_t* key);
    void addRoundKey(uint8_t* state, int round);
    void subBytes(uint8_t* state);
    void invSubBytes(uint8_t* state);
    void shiftRows(uint8_t* state);
    void invShiftRows(uint8_t* state);
    void mixColumns(uint8_t* state);
    void invMixColumns(uint8_t* state);
    void cipher(uint8_t* input, uint8_t* output);
    void invCipher(uint8_t* input, uint8_t* output);

    uint8_t roundKeys[176];
};

#endif
