#pragma once
// SHA-256 (FIPS 180-4) and RIPEMD-160 as __host__ __device__ code for the CUDA
// search kernel's hash160 step. Mirrors the vendored single-block fast paths of
// the proven CPU kernel (src/Secp256k1Scan.cpp). The kernel only ever hashes a
// 33-byte compressed pubkey, but these accept any length so the host tests can
// cover known-answer vectors. Host-tested in tests/test_gpu_hash.cpp vs OpenSSL.
#include "bcdgpu/hd.h"

namespace bcdgpu {

// ---- SHA-256 -------------------------------------------------------------
namespace sha_detail {

BCD_HD uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

BCD_HD void transform(uint32_t h[8], const uint8_t block[64]) {
    const uint32_t K[64] = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};
    uint32_t w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) | (uint32_t)block[i*4+3];
    for (int i = 16; i < 64; ++i) {
        const uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
        const uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (int i = 0; i < 64; ++i) {
        const uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
        const uint32_t ch = (e & f) ^ (~e & g);
        const uint32_t t1 = hh + S1 + ch + K[i] + w[i];
        const uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t t2 = S0 + maj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
}

}  // namespace sha_detail

BCD_HD void sha256(const uint8_t* data, uint32_t len, uint8_t out[32]) {
    uint32_t h[8] = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
                     0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    uint8_t block[64];
    uint32_t off = 0;
    while (len - off >= 64) { sha_detail::transform(h, data + off); off += 64; }
    const uint32_t rem = len - off;
    for (uint32_t i = 0; i < rem; ++i) block[i] = data[off + i];
    block[rem] = 0x80;
    if (rem >= 56) {
        for (uint32_t i = rem + 1; i < 64; ++i) block[i] = 0;
        sha_detail::transform(h, block);
        for (uint32_t i = 0; i < 56; ++i) block[i] = 0;
    } else {
        for (uint32_t i = rem + 1; i < 56; ++i) block[i] = 0;
    }
    const uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; ++i) block[56 + i] = (uint8_t)(bits >> (8 * (7 - i)));  // big-endian
    sha_detail::transform(h, block);
    for (int i = 0; i < 8; ++i) {
        out[i*4]   = (uint8_t)(h[i] >> 24); out[i*4+1] = (uint8_t)(h[i] >> 16);
        out[i*4+2] = (uint8_t)(h[i] >> 8);  out[i*4+3] = (uint8_t)(h[i]);
    }
}

// ---- RIPEMD-160 ----------------------------------------------------------
namespace rmd_detail {

BCD_HD uint32_t rotl(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
BCD_HD uint32_t f0(uint32_t x,uint32_t y,uint32_t z){return x^y^z;}
BCD_HD uint32_t f1(uint32_t x,uint32_t y,uint32_t z){return (x&y)|(~x&z);}
BCD_HD uint32_t f2(uint32_t x,uint32_t y,uint32_t z){return (x|~y)^z;}
BCD_HD uint32_t f3(uint32_t x,uint32_t y,uint32_t z){return (x&z)|(y&~z);}
BCD_HD uint32_t f4(uint32_t x,uint32_t y,uint32_t z){return x^(y|~z);}
BCD_HD uint32_t lf(int j,uint32_t x,uint32_t y,uint32_t z){
    if(j<16)return f0(x,y,z); if(j<32)return f1(x,y,z); if(j<48)return f2(x,y,z);
    if(j<64)return f3(x,y,z); return f4(x,y,z);}
BCD_HD uint32_t rf(int j,uint32_t x,uint32_t y,uint32_t z){
    if(j<16)return f4(x,y,z); if(j<32)return f3(x,y,z); if(j<48)return f2(x,y,z);
    if(j<64)return f1(x,y,z); return f0(x,y,z);}
BCD_HD uint32_t lk(int j){ if(j<16)return 0u; if(j<32)return 0x5A827999u; if(j<48)return 0x6ED9EBA1u; if(j<64)return 0x8F1BBCDCu; return 0xA953FD4Eu;}
BCD_HD uint32_t rk(int j){ if(j<16)return 0x50A28BE6u; if(j<32)return 0x5C4DD124u; if(j<48)return 0x6D703EF3u; if(j<64)return 0x7A6D76E9u; return 0u;}

BCD_HD void transform(uint32_t h[5], const uint8_t block[64]) {
    const int RL[80]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
        3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
        4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13};
    const int RR[80]={5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
        15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
        12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11};
    const int SL[80]={11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
        11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
        9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6};
    const int SR[80]={8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
        9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
        8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11};
    uint32_t w[16];
    for (int i = 0; i < 16; ++i)
        w[i] = (uint32_t)block[i*4] | ((uint32_t)block[i*4+1]<<8) | ((uint32_t)block[i*4+2]<<16) | ((uint32_t)block[i*4+3]<<24);
    uint32_t al=h[0],bl=h[1],cl=h[2],dl=h[3],el=h[4];
    uint32_t ar=h[0],br=h[1],cr=h[2],dr=h[3],er=h[4];
    for (int j = 0; j < 80; ++j) {
        uint32_t t = al + lf(j,bl,cl,dl) + w[RL[j]] + lk(j);
        t = rotl(t, SL[j]) + el; al=el; el=dl; dl=rotl(cl,10); cl=bl; bl=t;
        t = ar + rf(j,br,cr,dr) + w[RR[j]] + rk(j);
        t = rotl(t, SR[j]) + er; ar=er; er=dr; dr=rotl(cr,10); cr=br; br=t;
    }
    const uint32_t t = h[1] + cl + dr;
    h[1] = h[2] + dl + er; h[2] = h[3] + el + ar; h[3] = h[4] + al + br;
    h[4] = h[0] + bl + cr; h[0] = t;
}

}  // namespace rmd_detail

BCD_HD void ripemd160(const uint8_t* data, uint32_t len, uint8_t out[20]) {
    uint32_t h[5] = {0x67452301u,0xEFCDAB89u,0x98BADCFEu,0x10325476u,0xC3D2E1F0u};
    uint8_t block[64];
    uint32_t off = 0;
    while (len - off >= 64) { rmd_detail::transform(h, data + off); off += 64; }
    const uint32_t rem = len - off;
    for (uint32_t i = 0; i < rem; ++i) block[i] = data[off + i];
    block[rem] = 0x80;
    if (rem >= 56) {
        for (uint32_t i = rem + 1; i < 64; ++i) block[i] = 0;
        rmd_detail::transform(h, block);
        for (uint32_t i = 0; i < 56; ++i) block[i] = 0;
    } else {
        for (uint32_t i = rem + 1; i < 56; ++i) block[i] = 0;
    }
    const uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; ++i) block[56 + i] = (uint8_t)(bits >> (8 * i));  // little-endian
    rmd_detail::transform(h, block);
    for (int i = 0; i < 5; ++i) {
        out[i*4]   = (uint8_t)(h[i]);       out[i*4+1] = (uint8_t)(h[i] >> 8);
        out[i*4+2] = (uint8_t)(h[i] >> 16); out[i*4+3] = (uint8_t)(h[i] >> 24);
    }
}

// hash160 = RIPEMD-160(SHA-256(data))
BCD_HD void hash160(const uint8_t* data, uint32_t len, uint8_t out[20]) {
    uint8_t h32[32];
    sha256(data, len, h32);
    ripemd160(h32, 32, out);
}

}  // namespace bcdgpu
