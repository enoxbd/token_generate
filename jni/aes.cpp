#include "aes.hpp"
#include <cstring>
#include <sstream>
#include <iomanip>

const uint8_t AES128::sbox[256] = {
    // Full S-Box here (keep it short for now if needed)
    // You must fill this with standard AES S-Box values.
};

const uint8_t AES128::rcon[10] = {
    0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80,
    0x1B, 0x36
};

AES128::AES128(const std::string& keyStr) {
    memset(key, 0, 16);
    for (size_t i = 0; i < keyStr.size() && i < 16; ++i) {
        key[i] = keyStr[i];
    }
    KeyExpansion();
}

void AES128::KeyExpansion() {
    memcpy(roundKeys, key, 16);
    uint8_t temp[4];

    int bytesGenerated = 16;
    int rconIteration = 0;

    while (bytesGenerated < 176) {
        for (int i = 0; i < 4; ++i)
            temp[i] = roundKeys[bytesGenerated - 4 + i];

        if (bytesGenerated % 16 == 0) {
            uint8_t k = temp[0];
            temp[0] = sbox[temp[1]] ^ rcon[rconIteration++];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[k];
        }

        for (int i = 0; i < 4; ++i) {
            roundKeys[bytesGenerated] = roundKeys[bytesGenerated - 16] ^ temp[i];
            ++bytesGenerated;
        }
    }
}

void AES128::SubBytes(uint8_t* state) {
    for (int i = 0; i < 16; ++i)
        state[i] = sbox[state[i]];
}

void AES128::ShiftRows(uint8_t* state) {
    uint8_t tmp[16];

    tmp[0] = state[0];
    tmp[1] = state[5];
    tmp[2] = state[10];
    tmp[3] = state[15];

    tmp[4] = state[4];
    tmp[5] = state[9];
    tmp[6] = state[14];
    tmp[7] = state[3];

    tmp[8] = state[8];
    tmp[9] = state[13];
    tmp[10] = state[2];
    tmp[11] = state[7];

    tmp[12] = state[12];
    tmp[13] = state[1];
    tmp[14] = state[6];
    tmp[15] = state[11];

    memcpy(state, tmp, 16);
}

void AES128::MixColumns(uint8_t* state) {
    for (int i = 0; i < 4; ++i) {
        int idx = i * 4;
        uint8_t a = state[idx];
        uint8_t b = state[idx + 1];
        uint8_t c = state[idx + 2];
        uint8_t d = state[idx + 3];

        state[idx]     = (uint8_t)(2 * a ^ 3 * b ^ c ^ d);
        state[idx + 1] = (uint8_t)(a ^ 2 * b ^ 3 * c ^ d);
        state[idx + 2] = (uint8_t)(a ^ b ^ 2 * c ^ 3 * d);
        state[idx + 3] = (uint8_t)(3 * a ^ b ^ c ^ 2 * d);
    }
}

void AES128::AddRoundKey(uint8_t* state, int round) {
    for (int i = 0; i < 16; ++i)
        state[i] ^= roundKeys[round * 16 + i];
}

void AES128::Cipher(uint8_t* input, uint8_t* output) {
    uint8_t state[16];
    memcpy(state, input, 16);

    AddRoundKey(state, 0);
    for (int round = 1; round < 10; ++round) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, round);
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, 10);

    memcpy(output, state, 16);
}

std::string AES128::encrypt(const std::string& plaintext) {
    std::string padded = plaintext;
    while (padded.size() % 16 != 0) {
        padded += '\0';
    }

    std::ostringstream hexStream;
    for (size_t i = 0; i < padded.size(); i += 16) {
        uint8_t input[16], output[16];
        memcpy(input, padded.data() + i, 16);
        Cipher(input, output);
        for (int j = 0; j < 16; ++j) {
            hexStream << std::hex << std::setw(2) << std::setfill('0') << (int)output[j];
        }
    }
    return hexStream.str();
}
