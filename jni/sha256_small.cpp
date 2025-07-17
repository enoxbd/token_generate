#include "sha256_small.hpp"
#include <cstring>
#include <sstream>
#include <iomanip>

// SHA256 implementation (simple, small, portable)

namespace {

typedef unsigned char uint8;
typedef unsigned int uint32;
typedef unsigned long long uint64;

const uint32 k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

inline uint32 rotr(uint32 x, uint32 n) {
    return (x >> n) | (x << (32 - n));
}

inline uint32 ch(uint32 x, uint32 y, uint32 z) {
    return (x & y) ^ (~x & z);
}

inline uint32 maj(uint32 x, uint32 y, uint32 z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint32 bsig0(uint32 x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline uint32 bsig1(uint32 x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline uint32 ssig0(uint32 x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

inline uint32 ssig1(uint32 x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

void toBytes(uint32 val, uint8* bytes) {
    bytes[0] = (uint8)(val >> 24);
    bytes[1] = (uint8)(val >> 16);
    bytes[2] = (uint8)(val >> 8);
    bytes[3] = (uint8)(val);
}

uint32 toUint32(const uint8* bytes) {
    return ((uint32)bytes[0] << 24) | ((uint32)bytes[1] << 16) | ((uint32)bytes[2] << 8) | ((uint32)bytes[3]);
}

} // namespace

namespace SHA256 {

std::string hash(const std::string& input) {
    uint8 data[64];
    uint32 state[8] = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    };

    uint64 bitLen = 0;
    uint8 buffer[64];
    uint32 bufferLen = 0;

    auto transform = [&](const uint8 block[64]) {
        uint32 w[64];
        for (int i = 0; i < 16; i++) {
            w[i] = toUint32(block + i * 4);
        }
        for (int i = 16; i < 64; i++) {
            w[i] = ssig1(w[i - 2]) + w[i - 7] + ssig0(w[i - 15]) + w[i - 16];
        }

        uint32 a = state[0];
        uint32 b = state[1];
        uint32 c = state[2];
        uint32 d = state[3];
        uint32 e = state[4];
        uint32 f = state[5];
        uint32 g = state[6];
        uint32 h = state[7];

        for (int i = 0; i < 64; i++) {
            uint32 t1 = h + bsig1(e) + ch(e, f, g) + k[i] + w[i];
            uint32 t2 = bsig0(a) + maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    };

    for (char c : input) {
        buffer[bufferLen++] = static_cast<uint8>(c);
        bitLen += 8;
        if (bufferLen == 64) {
            transform(buffer);
            bufferLen = 0;
        }
    }

    // padding
    buffer[bufferLen++] = 0x80;
    if (bufferLen > 56) {
        while (bufferLen < 64) {
            buffer[bufferLen++] = 0x00;
        }
        transform(buffer);
        bufferLen = 0;
    }
    while (bufferLen < 56) {
        buffer[bufferLen++] = 0x00;
    }

    bitLen += input.size() * 8;
    for (int i = 7; i >= 0; --i) {
        buffer[bufferLen++] = (bitLen >> (i * 8)) & 0xff;
    }

    transform(buffer);

    std::stringstream ss;
    for (int i = 0; i < 8; ++i) {
        ss << std::hex << std::setw(8) << std::setfill('0') << state[i];
    }

    return ss.str();
}

} // namespace SHA256
