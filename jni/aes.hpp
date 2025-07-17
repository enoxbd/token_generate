#ifndef AES_HPP
#define AES_HPP

#include <cstdint>
#include <cstring>
#include <string>

class AES128 {
private:
    static const int Nb = 4;   // block size (in words): no of columns (fixed at 4 for AES)
    static const int Nk = 4;   // key length (in words): 4 for 128-bit key
    static const int Nr = 10;  // number of rounds: 10 for 128-bit key

    uint8_t RoundKey[176]; // 11 round keys * 16 bytes each

    // S-box
    static const uint8_t sbox[256];

    void KeyExpansion(const uint8_t* key);
    void AddRoundKey(uint8_t* state, int round);
    void SubBytes(uint8_t* state);
    void ShiftRows(uint8_t* state);
    void MixColumns(uint8_t* state);
    void Cipher(uint8_t* input, uint8_t* output);

    static uint8_t xtime(uint8_t x);

public:
    AES128(const uint8_t* key);
    void Encrypt(const uint8_t* input, uint8_t* output);
    std::string EncryptECB(const std::string& plaintext);
};

#endif // AES_HPP
