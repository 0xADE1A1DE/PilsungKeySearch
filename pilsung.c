#include "pilsung.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/sha.h> // For SHA1

// Creating pilsung_ctx with sbox aligned to cache sets
pilsung_ctx* pilsung_ctx_alloc(int sbox_align) {
    pilsung_ctx *ctx = (pilsung_ctx *)malloc(sizeof(pilsung_ctx) + 128);
    if (sbox_align == -1)
        return ctx;
    uintptr_t offset = ((uintptr_t)(ctx->sboxes)) % 64; 
    if (offset == sbox_align)
        return ctx;
    return (pilsung_ctx *)((uintptr_t)ctx + 64 - offset + sbox_align);
}

typedef uint8_t block_t[4][4];

static const size_t g_CryptoKeyLen = 32; // 256-bit key
static const size_t g_round_cnt = 11; // 11 rounds

// All combinations of 4 bits in 8-bit words
static const uint8_t Tree_Integer8[70] = {
  0x0F, 0x87, 0x47, 0x27, 0x17, 0xC3, 0x63, 0x33, 0x1B, 0xA3,
  0x53, 0x2B, 0x93, 0x4B, 0x8B, 0xE1, 0x71, 0x39, 0x1D, 0xB1,
  0x59, 0x2D, 0x99, 0x4D, 0x8D, 0xD1, 0x69, 0x35, 0xA9, 0x55,
  0x95, 0xC9, 0x65, 0xA5, 0xC5, 0xF0, 0x78, 0x3C, 0x1E, 0xB8,
  0x5C, 0x2E, 0x9C, 0x4E, 0x8E, 0xD8, 0x6C, 0x36, 0xAC, 0x56,
  0x96, 0xCC, 0x66, 0xA6, 0xC6, 0xE8, 0x74, 0x3A, 0xB4, 0x5A,
  0x9A, 0xD4, 0x6A, 0xAA, 0xCA, 0xE4, 0x72, 0xB2, 0xD2, 0xE2
};

// All combinations of 2 bits in 4-bit words
static const uint8_t Tree_Integer4[6] = {
  0x03, 0x09, 0x05, 0x0C, 0x06, 0x0A
};

// multiply by x modulo x^8 + x^4 + x^3 + x + 1
static uint8_t xtime(uint8_t b) {
  return (b << 1) ^ ((b & 0x80) ? 0x1b : 0);
}

// GF(2^8) generic multiplication, double-and-add
static uint8_t multiply(uint8_t a, uint8_t b) {
  uint8_t c = 0;
  for(size_t i = 0; i < 8; ++i) {
    if((b >> i) & 1)
      c ^= a;
    a = xtime(a);
  }
  return c;
}

static uint8_t rotate_left(uint8_t x, size_t c) {
  return (x << c % 8) | (x >> (8 - c) % 8);
}

// Unmodified AES S-box
// See SubByte2 for the Pilsung version
uint8_t SubByte(const uint8_t x0) {
  const uint8_t  x1 = multiply( x0,  x0); // x^2
  const uint8_t  x2 = multiply( x1,  x0); // x^3
  const uint8_t  x3 = multiply( x2,  x2); // x^6
  const uint8_t  x4 = multiply( x3,  x3); // x^12
  const uint8_t  x5 = multiply( x4,  x2); // x^15
  const uint8_t  x6 = multiply( x5,  x5); // x^30
  const uint8_t  x7 = multiply( x6,  x6); // x^60
  const uint8_t  x8 = multiply( x7,  x2); // x^63
  const uint8_t  x9 = multiply( x8,  x8); // x^126
  const uint8_t x10 = multiply( x9,  x0); // x^127
  const uint8_t x11 = multiply(x10, x10); // x^254 = x^-1
  return x11 ^ rotate_left(x11, 1) ^ rotate_left(x11, 2) ^
         rotate_left(x11, 3) ^ rotate_left(x11, 4) ^ 0x63;
}

static void RotWord(uint8_t w[4]) {
  const uint8_t t = w[0];
  w[0] = w[1];
  w[1] = w[2];
  w[2] = w[3];
  w[3] = t;
}

static void SubWord(uint8_t w[4]) {
  for(size_t i = 0; i < 4; ++i)
    w[i] = SubByte(w[i]);
}

// Distribution sort --- sort array p of size n according to 0-1 array s
// Assumes s has n / 2 zeros and n / 2 ones
void Get_One(const uint8_t * s, uint8_t * p, size_t n, uint8_t * buf) {
  size_t a = 0, b = 0;
  for(size_t i = 0; i < n; ++i) {
    if( s[i] )
      buf[n / 2 + a++] = p[i];
    else
      buf[b++] = p[i];
  }
  memcpy(p, buf, n);
}

// Permute the bits of input_mask according to computed permutation
uint8_t Get_PeSb(const uint8_t input_mask, pilsung_ctx * ctx) {
  uint8_t x = 0;
  for(size_t i = 0; i < 8; ++i) {
    if( (1UL << i) & input_mask )
      x |= 1UL << ctx->current_permutation_8[i];
  }
  return x ^ ctx->sbox_xor_constant;
}


// Generate a random permutation of [0..7] at ctx->current_permutation_8
void Get_P8forSEnc(const uint8_t input_mask, pilsung_ctx * ctx) {
  uint8_t coinflips[24];

  // Random 4-bit subset
  const uint8_t v0 = Tree_Integer8[input_mask % 70];
  for(size_t i = 0; i < 8; ++i) {
    coinflips[i] = (v0 >> (7 - i)) & 1;
  }

  const uint8_t v1 = (Tree_Integer4[(input_mask & 0x0F) % 6] << 0) |
                     (Tree_Integer4[(input_mask >> 4) % 6] << 4);
  for(size_t i = 0; i < 8; ++i) {
    coinflips[i+8] = (v1 >> (7 - i)) & 1;
  }

  for(size_t i = 0; i < 8; i += 2) {
    if( input_mask & (3 << i) ) {
      coinflips[16+i+0] = 1;
      coinflips[16+i+1] = 0;
    } else {
      coinflips[16+i+0] = 0;
      coinflips[16+i+1] = 1;
    }
  }

  // Initialize permutation with identity
  for(size_t i = 0; i < 8; ++i)
    ctx->current_permutation_8[i] = i;

  // Iterative version of the Rao-Sandelius shuffle
  uint8_t scratch[32];
  for(size_t i = 0; i < 3; ++i) {
    const size_t bins = 1 << i;       // number of subgroups
    const size_t size = 1 << (3 - i); // size of each subgroup
    for(size_t j = 0; j < bins; ++j) {
      Get_One(&coinflips[i * 8 + j * size], &ctx->current_permutation_8[j * size], size, scratch);
    }
  }
}

// Generate a random permutation of [0..15] at output
void Get_P16Enc(const uint8_t * input, uint8_t * output) {
  uint8_t coinflips[64];

  // coin flips for first level
  for(size_t i = 0; i < 4; ++i) {
    const uint8_t v0 = Tree_Integer4[(input[i] ^ input[i+4]) % 6];
    for(size_t j = 0; j < 4; ++j) {
      coinflips[4 * i + j] = (v0 >> (3 - j)) & 1;
    }
  }

  // coin flips for second level
  for(size_t i = 0; i < 8; ++i) {
    if((input[i] >> i) & 1) {
      coinflips[16 + 2*i + 0] = 1;
      coinflips[16 + 2*i + 1] = 0;
    } else {
      coinflips[16 + 2*i + 0] = 0;
      coinflips[16 + 2*i + 1] = 1;
    }
  }

  // coin flips for third level
  for(size_t i = 0; i < 4; ++i) {
    const uint8_t v1 = Tree_Integer4[(input[i+8] ^ input[i+12]) % 6];
    for(size_t j = 0; j < 4; ++j) {
      coinflips[32+4*i+j] = (v1 >> (3 - j)) & 1;
    }
  }

  // coin flips for fourth level
  for(size_t i = 0; i < 8; ++i) {
    if((input[8+i] >> i) & 1) {
      coinflips[48 + 2*i + 0] = 1;
      coinflips[48 + 2*i + 1] = 0;
    } else {
      coinflips[48 + 2*i + 0] = 0;
      coinflips[48 + 2*i + 1] = 1;
    }
  }

  // Initialize permutation with identity
  for(size_t i = 0; i < 16; ++i)
    output[i] = i;

  // Iterative version of the Rao-Sandelius shuffle
  uint8_t scratch[32];
  for(size_t i = 0; i < 4; ++i) {
    const size_t bins = 1 << i;       // number of subgroups
    const size_t size = 1 << (4 - i); // size of each subgroup
    for(size_t j = 0; j < bins; ++j) {
      Get_One(&coinflips[i * 16 + j * size], &output[j * size], size, scratch);
    }
  }
}

// Generate all necessary S-boxes
void Get_VSboxAll(pilsung_ctx * ctx) {
  for(size_t rounds = 1; rounds < g_round_cnt; ++rounds) {
    for(size_t i = 0; i < 4; ++i) {
      for(size_t j = 0; j < 4; ++j) {
        Get_P8forSEnc(ctx->e_key[j + 4 * i + 16 * rounds], ctx);
        for(size_t k = 0; k < 256; ++k) {
          ctx->sboxes[rounds][i][j][k] = Get_PeSb(SubByte(k), ctx);
        }
      }
    }
  }
}


// Generate all necessary P-boxes
void Get_VPboxAll(pilsung_ctx * ctx) {
  for(size_t rounds = 1; rounds < g_round_cnt; ++rounds) {
    Get_P16Enc(&ctx->e_key[16 * rounds], ctx->pboxes[rounds]);
  }
}

void InitVar(pilsung_ctx * ctx) {
  ctx->sbox_xor_constant = 3;
}

void gen_enc_perm(pilsung_ctx * ctx) {
  InitVar(ctx);
  Get_VSboxAll(ctx);
  Get_VPboxAll(ctx);
}

// Pass 16 bytes through SHA-1, for some reason
void cfShaSign(uint8_t * out, uint8_t * in, size_t inlen) {
  while(inlen > 0) {
    const size_t blocklen = inlen < 16 ? inlen : 16;
    uint8_t digest[20];
    SHA1(in, blocklen, digest);
    // Pilsung's tweak to SHA-1
    for(size_t i = 0; i < 20; i += 4)
      digest[i+3] ^= 0xFF;
    memcpy(out, digest, blocklen);
    out += blocklen, in += blocklen, inlen -= blocklen;
  }
}

void pilsung_shakey(uint8_t * out, const uint8_t * in, size_t inlen, size_t outlen) {
  uint8_t * buffer1 = (uint8_t *)calloc(1, outlen);
  uint8_t * buffer2 = (uint8_t *)calloc(1, outlen);
  uint8_t buffer3[288] = {0};
  uint8_t buffer4[288] = {0};

  if(inlen >= outlen) {
    size_t inputlen = inlen < 256 ? inlen : 256;

    memcpy(buffer3, in, inputlen);
    memcpy(buffer4, buffer3, 32);

    while(inputlen > 0) {
      const size_t len = inputlen < 32 ? inputlen : 32;
      memcpy(buffer1, in, len);
      cfShaSign(buffer2, buffer1, len);
      for(size_t i = 0; i < len; ++i)
        buffer4[i] ^= buffer2[i];
      inputlen -= len;
      in += len;
    }
    memcpy(out, buffer4, outlen);
  } else { /* outlen < inlen */
    memcpy(buffer1, in, inlen);
    while(outlen > 0) {
      const size_t len = outlen < inlen ? outlen : inlen;
      cfShaSign(buffer2, buffer1, inlen);
      memcpy(buffer1, buffer2, inlen);
      memcpy(out, buffer2, inlen);
      out += len;
      outlen -= len;
    }
  }

  free(buffer1);
  free(buffer2);
}

void pilsung_expand_roundkey(const uint8_t * k, uint8_t * out, size_t Nr) {
  const size_t Nk = Nr - 6; // 5
  uint8_t (*e_key)[4] = (uint8_t (*)[4])out;
  uint8_t rcon = 1;
  for(size_t i = 0; i < Nk; ++i)
    for(size_t j = 0; j < 4; ++j)
      e_key[i][j] = k[4*i+j];
  for(size_t i = Nk; i < 4 * (Nr + 1); ++i) {
    uint8_t temp[4];
    for(size_t j = 0; j < 4; ++j)
      temp[j] = e_key[i-1][j];
    if(i % Nk == 0) {
      RotWord(temp);
      SubWord(temp);
      temp[0] ^= rcon;
      rcon = xtime(rcon);
    } else if (Nk > 6 && i % Nk == 4) {
      SubWord(temp);
    }
    for(size_t j = 0; j < 4; ++j)
      e_key[i][j] = e_key[i - Nk][j] ^ temp[j];
  }
}

void pilsung_expand_key(const uint8_t * k, size_t klen, pilsung_ctx * ctx) {
  uint8_t derived[32] = {0};
  pilsung_shakey(derived, k, klen, g_CryptoKeyLen);
  pilsung_expand_roundkey(derived, ctx->e_key, g_round_cnt);
}

void pilsung_set_key(pilsung_ctx * ctx, const uint8_t * k, size_t klen) {
  memset(ctx, 0, sizeof(*ctx));
  pilsung_expand_key(k, klen, ctx);
  gen_enc_perm(ctx);
}

static uint8_t SubByte2(const pilsung_ctx * ctx, size_t r, size_t i, size_t j, const uint8_t x0) {
  return ctx->sboxes[r][i][j][x0];
}

static void SubBytes(const pilsung_ctx * ctx, size_t round, block_t block) {
  for(size_t i = 0; i < 4; ++i)
    for(size_t j = 0; j < 4; ++j)
      block[i][j] = SubByte2(ctx, round, i, j, block[i][j]);
}

static void ShiftRows(const pilsung_ctx * ctx, size_t round, block_t block) {
  uint8_t copy[16];

  for(size_t i = 0; i < 4; ++i)
    for(size_t j = 0; j < 4; ++j)
      copy[i*4 + j] = block[i][j];

  for(size_t i = 0; i < 4; ++i)
    for(size_t j = 0; j < 4; ++j)
    block[i][j] = copy[ctx->pboxes[round][i*4 + j]];
}

static void MixColumns(block_t block) {
  for(size_t i = 0; i < 4; ++i) {
    const uint8_t c0 = block[i][0];
    const uint8_t c1 = block[i][1];
    const uint8_t c2 = block[i][2];
    const uint8_t c3 = block[i][3];
    block[i][0] = xtime(c0 ^ c1) ^ c1 ^ c2 ^ c3;
    block[i][1] = c0 ^ xtime(c1 ^ c2) ^ c2 ^ c3;
    block[i][2] = c0 ^ c1 ^ xtime(c2 ^ c3) ^ c3;
    block[i][3] = xtime(c0 ^ c3) ^ c0 ^ c1 ^ c2;
  }
}

static void AddRoundKey(block_t block, const uint8_t k[][4]) {
  for(size_t i = 0; i < 4; ++i)
    for(size_t j = 0; j < 4; ++j)
      block[i][j] ^= k[i][j];
}

void pilsung_encrypt(const pilsung_ctx * ctx, uint8_t output[16], const uint8_t input[16]) {
  block_t block;

  for(size_t i = 0; i < 4; ++i)
    for(size_t j = 0; j < 4; ++j)
      block[i][j] = input[i * 4 + j];

  AddRoundKey(block, (const uint8_t (*)[4])&ctx->e_key[0]);
  for(size_t round = 1; round < 10; ++round) {
    SubBytes(ctx, round, block);
    ShiftRows(ctx, round, block);
    MixColumns(block);
    AddRoundKey(block, (const uint8_t (*)[4])&ctx->e_key[16 * round]);
  }
  SubBytes(ctx, 10, block);
  ShiftRows(ctx, 10, block);
  // No MixColumns
  AddRoundKey(block, (const uint8_t (*)[4])&ctx->e_key[16 * 10]);

  for(size_t i = 0; i < 4; ++i)
    for(size_t j = 0; j < 4; ++j)
      output[i * 4 + j] = block[i][j];
}
