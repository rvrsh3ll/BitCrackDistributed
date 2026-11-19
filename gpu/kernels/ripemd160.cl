// OpenCL implementation of RIPEMD-160 hashing

#ifndef RIPEMD160_CL
#define RIPEMD160_CL

__constant uint RMD_H0[5] = {
    0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
};

uint rotl(uint x, int n) { return (x << n) | (x >> (32 - n)); }

uint rmd_f(uint x, uint y, uint z) { return x ^ y ^ z; }
uint rmd_g(uint x, uint y, uint z) { return (x & y) | (~x & z); }
uint rmd_h(uint x, uint y, uint z) { return (x | ~y) ^ z; }
uint rmd_i(uint x, uint y, uint z) { return (x & z) | (y & ~z); }
uint rmd_j(uint x, uint y, uint z) { return x ^ (y | ~z); }

void ripemd160_transform(__private uint state[5], __private const uchar block[64]) {
    uint x[16];
    uint al, bl, cl, dl, el, ar, br, cr, dr, er;

    for (int i = 0; i < 16; i++) {
        x[i] = ((uint)block[i * 4]) | ((uint)block[i * 4 + 1] << 8) |
               ((uint)block[i * 4 + 2] << 16) | ((uint)block[i * 4 + 3] << 24);
    }

    al = ar = state[0];
    bl = br = state[1];
    cl = cr = state[2];
    dl = dr = state[3];
    el = er = state[4];

    for (int i = 0; i < 16; i++) {
        uint t = al + rmd_f(bl, cl, dl) + x[i];
        al = el; el = dl; dl = rotl(cl, 10); cl = bl;
        bl = rotl(t, 11) + el;
    }

    for (int i = 0; i < 16; i++) {
        uint t = ar + rmd_j(br, cr, dr) + x[15 - i] + 0x50A28BE6;
        ar = er; er = dr; dr = rotl(cr, 10); cr = br;
        br = rotl(t, 11) + er;
    }

    state[0] += al;
    state[1] += bl;
    state[2] += cl;
    state[3] += dl;
    state[4] += el;
}

__kernel void ripemd160Hash(
    __global const uchar* input,
    __global uchar* output,
    int num_hashes
) {
    int idx = get_global_id(0);
    if (idx >= num_hashes) return;

    uint state[5];
    for (int i = 0; i < 5; i++) {
        state[i] = RMD_H0[i];
    }

    uchar block[64];
    for (int i = 0; i < 32; i++) {
        block[i] = input[idx * 32 + i];
    }
    for (int i = 32; i < 64; i++) {
        block[i] = 0;
    }
    block[32] = 0x80;

    ripemd160_transform(state, block);

    for (int i = 0; i < 5; i++) {
        output[idx * 20 + i * 4] = state[i] & 0xFF;
        output[idx * 20 + i * 4 + 1] = (state[i] >> 8) & 0xFF;
        output[idx * 20 + i * 4 + 2] = (state[i] >> 16) & 0xFF;
        output[idx * 20 + i * 4 + 3] = (state[i] >> 24) & 0xFF;
    }
}

#endif // RIPEMD160_CL
