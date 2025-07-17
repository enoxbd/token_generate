#ifndef SHA256_SMALL_HPP
#define SHA256_SMALL_HPP

#include <string>
#include <cstring>
#include <sstream>
#include <iomanip>

typedef unsigned char BYTE;
typedef unsigned int  WORD;

#define ROTLEFT(a,b) ((a << b) | (a >> (32-b)))
#define ROTRIGHT(a,b) ((a >> b) | (a << (32-b)))
#define CH(x,y,z) ((x & y) ^ (~x & z))
#define MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ (x >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ (x >> 10))

const WORD k[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

class SHA256 {
public:
    SHA256() { init(); }

    void update(const BYTE *data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            dataBuffer[dataLength] = data[i];
            dataLength++;
            if (dataLength == 64) {
                transform();
                totalLength += 512;
                dataLength = 0;
            }
        }
    }

    void final(BYTE hash[32]) {
        totalLength += dataLength * 8;
        dataBuffer[dataLength++] = 0x80;

        if (dataLength > 56) {
            while (dataLength < 64) dataBuffer[dataLength++] = 0x00;
            transform();
            dataLength = 0;
        }

        while (dataLength < 56) dataBuffer[dataLength++] = 0x00;

        for (int i = 7; i >= 0; --i)
            dataBuffer[dataLength++] = totalLength >> (i * 8);

        transform();

        for (int i = 0; i < 4; ++i) {
            for (int j = 0; j < 8; ++j) {
                hash[j * 4 + i] = (state[j] >> (24 - i * 8)) & 0x000000ff;
            }
        }
    }

private:
    BYTE dataBuffer[64];
    WORD state[8];
    size_t dataLength;
    size_t totalLength;

    void init() {
        dataLength = 0;
        totalLength = 0;
        state[0] = 0x6a09e667;
        state[1] = 0xbb67ae85;
        state[2] = 0x3c6ef372;
        state[3] = 0xa54ff53a;
        state[4] = 0x510e527f;
        state[5] = 0x9b05688c;
        state[6] = 0x1f83d9ab;
        state[7] = 0x5be0cd19;
    }

    void transform() {
        WORD a, b, c, d, e, f, g, h, t1, t2, m[64];
        for (int i = 0, j = 0; i < 16; ++i, j += 4)
            m[i] = (dataBuffer[j] << 24) | (dataBuffer[j + 1] << 16) | (dataBuffer[j + 2] << 8) | (dataBuffer[j + 3]);
        for (int i = 16; i < 64; ++i)
            m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

        a = state[0]; b = state[1]; c = state[2]; d = state[3];
        e = state[4]; f = state[5]; g = state[6]; h = state[7];

        for (int i = 0; i < 64; ++i) {
            t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
            t2 = EP0(a) + MAJ(a, b, c);
            h = g; g = f; f = e;
            e = d + t1;
            d = c; c = b; b = a;
            a = t1 + t2;
        }

        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }
};

// Convert string to SHA256 hex digest
inline std::string sha256(const std::string& input) {
    BYTE hash[32];
    SHA256 ctx;
    ctx.update((const BYTE*)input.c_str(), input.length());
    ctx.final(hash);

    std::stringstream ss;
    for (int i = 0; i < 32; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return ss.str();
}

#endif // SHA256_SMALL_HPP
