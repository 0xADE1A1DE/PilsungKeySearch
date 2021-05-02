#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "perm.h"
#include "tables.h"

struct tables *tables;

void mkmod6() {
  for (uint32_t i = 0; i < 0x10000; i++) 
    tables->mod6[i] = ((i >> 8)%6*6 + (i & 0xff)%6);
}

// All combinations of 2 bits in 4-bit words
static const uint8_t Tree_Integer4[6] = {
  0x03, 0x09, 0x05, 0x0C, 0x06, 0x0A
};


// Distribution sort --- sort array p of size n according to 0-1 array s
// Assumes s has n / 2 zeros and n / 2 ones
void GetOne(const uint8_t * s, uint8_t * p, uint32_t n, uint8_t * buf) {
  uint32_t a = 0, b = 0;
  for(uint32_t i = 0; i < n; ++i) {
    if( s[i] )
      buf[n / 2 + a++] = p[i];
    else
      buf[b++] = p[i];
  }
  memcpy(p, buf, n);
}


void setCoinFlips(uint64_t key, uint8_t coinflips[32]) {
  uint8_t input[8];

  for (int i = 0; i < 8; i++)
    input[i] = (key >> (i*8)) & 0xff;
  // coin flips for first level
  for(uint32_t i = 0; i < 4; ++i) {
    const uint8_t v0 = Tree_Integer4[(input[i] ^ input[i+4]) % 6];
    for(uint32_t j = 0; j < 4; ++j) {
      coinflips[4 * i + j] = (v0 >> (3 - j)) & 1;
    }
  }

  // coin flips for second level
  for(uint32_t i = 0; i < 8; ++i) {
    if((input[i] >> i) & 1) {
      coinflips[16 + 2*i + 0] = 1;
      coinflips[16 + 2*i + 1] = 0;
    } else {
      coinflips[16 + 2*i + 0] = 0;
      coinflips[16 + 2*i + 1] = 1;
    }
  }
}


// Generate Pilsung's levels 1 and 2 permutation
int Get_P16Enc12(uint64_t key, uint8_t maps[4]) {
  uint8_t coinflips[32];
  uint8_t output[16];

  setCoinFlips(key, coinflips);

  for (int i = 0; i < 16; i++)
    output[i] = i&0x3;
  // Iterative version of the Rao-Sandelius shuffle
  uint8_t scratch[32];
  for(uint32_t i = 0; i < 2; ++i) {
    const uint32_t bins = 1 << i;       // number of subgroups
    const uint32_t size = 1 << (4 - i); // size of each subgroup
    for(uint32_t j = 0; j < bins; ++j) {
      GetOne(&coinflips[i * 16 + j * size], &output[j * size], size, scratch);
    }
  }

  int valid = 0x0f;
  for (int i = 0; i < 4; i++)
    maps[i] = 0xff;

  for (int row = 0; row < 4; row++) {
    int mask = 0x03 << (row * 2);
    for (int col = 0; col < 4; col++) {
      maps[output[row*4+col]] &= (~mask | (col << (row * 2)));
      if ((maps[output[row*4+col]] & mask) != (col << (row * 2)))
	valid &= ~(1<<output[row*4+col]);
    }
  }
  return valid;
}

// Generate Pilsung's levels 3 and 4 permutation
void Get_P16Enc34(uint64_t key, uint8_t maps[4]) {
  uint8_t coinflips[32];
  uint8_t output[16];

  setCoinFlips(key, coinflips);

  for (int i = 0; i < 16; i++)
    output[i] = i&3;
  // Iterative version of the Rao-Sandelius shuffle
  uint8_t scratch[32];
  for(uint32_t i = 0; i < 2; ++i) {
    const uint32_t bins = 4 << i;       // number of subgroups
    const uint32_t size = 1 << (2 - i); // size of each subgroup
    for(uint32_t j = 0; j < bins; ++j) {
      GetOne(&coinflips[i * 16 + j * size], &output[j * size], size, scratch);
    }
  }

  for (int col = 0; col<4; col++) {
    int map = 0;
    for (int row = 0; row < 4; row++) 
      map |= output[row * 4 + col]<<(row * 2);
    maps[col] = map;
  }
}

int valid12[256];

void mkmap12() {
  for (uint32_t perm = 0; perm < NPERMS; perm++) {
    uint64_t key = permtokey(perm);
    uint8_t maps[4];
    int valid = Get_P16Enc12(key, maps);
    tables->preservesany[LEVEL1(perm)] |= valid;
    for (int i = 0; i < 4; i++) {
      if (valid & (1<<i)) {
	tables->preserves[i][perm>>6] |= (1ULL<<(perm & 0x3f));
	valid12[maps[i]] = 1;
      }
      tables->map12[i][perm] = maps[i];
    }
  }

#if 0
  char *n[16] = {
    "0000","0001","0010","0011","0100","0101","0110","0111",
    "1000","1001","1010","1011","1100","1101","1110","1111"};
  for (int i = 0; i < 72; i++) {
    printf ("%4d:", i * 18);
    for (int j = 0; j < 18; j++)
      printf(" %s", n[tables->preservesany[i*18+j]]);
    printf("\n");
  }
#endif
}

void mkmap34() {
  for (uint32_t perm = 0; perm < NPERMS; perm++) {
    uint64_t key = permtokey(perm);
    uint8_t maps[4];
    Get_P16Enc34(key, maps);
    for (int i = 0; i < 4; i++)  {
      tables->map34[i][perm] = maps[i];
      if (valid12[maps[i]]) {
	tables->valid34[perm>>6] |= (1ULL<<(perm & 0x3f));
      }
    }
  }
}

void mksbox() {
  extern uint8_t SubByte(uint8_t);
  for (int i = 0; i < 256; i++) {
    tables->sbox[i] = SubByte(i);
  }
}



void gentables() {
  tables = malloc(sizeof(struct tables));
  memset(tables, 0, sizeof(struct tables));
  mksbox();
  mkmod6();
  mkmap12();
  mkmap34();
}
