#ifndef PILSUNG_H
#define PILSUNG_H

#include <stdint.h>
#include <stddef.h>

typedef struct pilsung_ctx {
  uint8_t sbox_xor_constant; // = 3
  uint8_t sboxes[30][4][4][256]; // S-boxes
  uint8_t pboxes[30][16]; // P-boxes
  uint8_t current_permutation_8[8]; // used for temporary storage
  uint8_t e_key[15 * 16]; // AES scheduled key
} pilsung_ctx;

// Creating pilsung_ctx with sbox aligned to cache sets
pilsung_ctx* pilsung_ctx_alloc(int sbox_align);

void pilsung_shakey(uint8_t *out, const uint8_t *in, size_t inlen, size_t outlen);

void pilsung_expand_roundkey(const uint8_t *k, uint8_t *out, size_t Nr);

void pilsung_expand_key(const uint8_t *k, size_t klen, pilsung_ctx *ctx);

void pilsung_set_key(pilsung_ctx *ctx, const uint8_t *k, size_t klen);

void pilsung_encrypt(const pilsung_ctx *ctx, uint8_t output[16], const uint8_t input[16]);

#endif