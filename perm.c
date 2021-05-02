#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "perm.h"
#include "tables.h"
#include "rand.h"

uint32_t keytoperm(uint64_t key) {
  uint32_t level1 = key ^ (key >> 32);
  key &= 0x8040201008040201UL;
  uint32_t level2 = key | (key>>32);
  level2 |= level2>>16;
  level2 |= level2>>8;
  uint32_t t = tables->mod6[level1>>16];
  return (t<<13) + (t<<10) + (tables->mod6[level1 & 0xffff]<<8) + (level2& 0xff);
}


uint64_t permtokey(uint32_t permid) {
  uint64_t key = 0;

  uint32_t level1 = permid>>8;
  key += level1 % 6;
  key += ((level1/6)%6) << 8;
  key += ((level1/36)%6) << 16;
  key += ((level1/216)%6) << 24;

  for (int i = 0; i < 8; i++)
    key ^= (0x100000001UL * ((permid^(key>>8*i))&(1<<i))) << (8*(i&3));


  return key;
}

/*
static inline uint32_t rdrand32(void) {
  uint32_t r; 
  asm __volatile__ ("rdrand %0":"=r" (r)); 
  return r;
}


static inline uint64_t rdrand64(void) {
  uint64_t r; 
  asm __volatile__ ("rdrand %0":"=r" (r)); 
  return r;
}
*/
static struct randstate rs;

uint8_t randkey(uint64_t key[2]) {
  uint64_t keyl, keyh;
 
  uint8_t map, column;
  uint32_t perml, permh;
  uint8_t lpreserves,nextpreserves;
  uint8_t valid;

  do {
    valid = 0;
    keyl = prand(&rs);
    perml = keytoperm(keyl);
    for (int i = 0; i < 4; i++) 
      if (PRESERVES(perml, i))
	valid |= 1<<i;
    if (valid == 0)
      continue;

  }  while (!valid);


  do {
    valid = 0;
    keyh = prand(&rs);
    permh = keytoperm(keyh);
    if (!VALID34(permh))
      continue;
    for (int i = 0; i < 4; i++) {
      if (PRESERVES(perml, i)) {
	for (int j = 0; j < 4; j++)
	  if (MAP12(perml, i) == MAP34(permh, j))
	    valid |= 1 << j;
      }
    }
  } while (!valid);
  key[0] = keyl;
  key[1] = keyh;
  return valid;
}

