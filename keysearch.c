#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>

#include "perm.h"
#include "tables.h"
#include "rand.h"


struct opts {
  int printhex;
  int startround;
  int printround;
  int targetround;
  int count;
  int duration;
};

struct opts opts = {0, 3, 8, 12, 10000, 0};
uint32_t rk[12*4];

void parseopts(int ac, char **av) {
  int opt;
  char *p;
  long int d;
  while ((opt = getopt(ac, av, "d:p:c:s:t:x")) != -1) {
    switch(opt) {
    case 'x': 
      opts.printhex = 1;
      break;
    case 'c': 
      opts.count = atoi(optarg);
      break;
    case 's': 
      opts.startround = atoi(optarg);
      break;
    case 'p': 
      opts.printround = atoi(optarg);
      break;
    case 't': 
      opts.targetround = atoi(optarg);
      break;
    case 'd': 
      d = strtol(optarg, &p, 10);
      switch (*p) {
	case 's':
	case 'S':
	  opts.duration = d;
	  break;
	case 'm':
	case 'M':
	case '\0':
	  opts.duration = d * 60;
	  break;
	case 'h':
	case 'H':
	  opts.duration = d * 3600;
	  break;
	case 'd':
	case 'D':
	  opts.duration = d * 86400;
	  break;
      }
      break;
    default:
      fprintf(stderr, "Usage: %s [-xe] [-d <duration>] [-c <millions>] [-s <startround>] [-p <printround>][-t <targetround>]\n", av[0]);
      exit(1);
    }
  }
  if (opts.printround>opts.targetround)
    opts.printround = opts.targetround;
  if (opts.duration > 0)
    opts.count = INT_MAX;
}

static inline uint64_t rdtscp64() {
  uint32_t low, high;
  asm volatile ("rdtscp": "=a" (low), "=d" (high) :: "ecx");
  return (((uint64_t)high) << 32) | low;
}



void printmap(uint8_t m) {
  for (int i = 0; i < 8; i+=2) {
    if (i!= 0)
      printf("-");
    printf("%d", (m>>i)&3);
  }
  printf(" ");
}

uint32_t rotsub(uint32_t v) {
  return 
    SBOX((v >>  8) & 0xff)       |
    SBOX((v >> 16) & 0xff) <<  8 |
    SBOX((v >> 24) & 0xff) << 16 |
    SBOX((v      ) & 0xff) << 24;
}


uint32_t getkeyword(uint32_t mod, uint32_t prev, int word) {
  if (word % 5 == 0)
    prev = rotsub(prev) ^ (1<<(word/5 - 1)); // Need to fix rcon for round 12...
  return prev ^ mod;
}

void fillkey(int startword, int endword) {
  while (startword < endword)  {
    rk[startword] = getkeyword(rk[startword-5], rk[startword-1], startword);
    startword++;
  }
}


void testkey(const uint8_t *k) {
  extern void pilsung_expand_roundkey(const uint8_t *, uint8_t *, size_t);
  uint8_t out[16*12];
  pilsung_expand_roundkey(k, (uint8_t *)out, 11);
  for (int i = 0; i < 5; i++)
    rk[i] = ((uint32_t *)k)[i];
  fillkey(5, 12*4);
  for (int i = 0; i < 12; i++) {
    printf("%2d: ", i);
    for (int j =0; j < 8; j++)
      printf("%02x", out[i*16+7-j]);
    printf(".");
    for (int j =0; j < 8; j++)
      printf("%02x", out[i*16+15-j]);
    printf("     ");
    printf("%08x%08x.%08x%08x\n", rk[i*4+1], rk[i*4], rk[i*4+3], rk[i*4+2]);
  }
}






int validateround(int round, int col) {
  uint64_t kl = rk[round*4] | ((uint64_t)(rk[round*4+1]) << 32);
  uint64_t kh = rk[round*4+2] | ((uint64_t)(rk[round*4+3]) << 32);
  int pl = keytoperm(kl);
  int ph = keytoperm(kh);

  if (!VALID34(ph))
    return -1;

  if (!CANPRESERVECOL(pl, col)) 
    return -1;

  if (!PRESERVES(pl, col))
    return -1;

  for (int i = 0; i < 4; i++)
    if (MAP34(ph, i) == MAP12(pl, col))
      return i;
  return -1;
}


#define ENDROUND 12
int preservesto(int startround, int col) {
  //fillkey(startround*4, ENDROUND*4);
  for (int round = startround; round < ENDROUND; round++) {
    fillkey(round*4, (round+1)*4);
    int next = validateround(round, col);
    if (next == -1)
      return round;
    col = next;
  }
  return ENDROUND;
}

void printkey(int to) {
  printf(opts.printhex ? "uint8_t key[] = {\n" :"---------------------\n", to);
  for (int round = opts.startround; round < to; round++) {
    printf(opts.printhex ? "  " : "RK_%-2d: ", round);
    for (int i = 0; i < 4; i++) {
      printf(opts.printhex ? "0x%02x, 0x%02x, 0x%02x, 0x%02x, " : "%02x %02x %02x %02x  ",
	  rk[round * 4 + i] & 0xff, 
	  (rk[round * 4 + i]>>8) & 0xff, 
	  (rk[round * 4 + i]>>16) & 0xff, 
	  (rk[round * 4 + i]>>24) & 0xff);
    }
    printf("\n");
  }
  if (opts.printhex)
    printf("};\n");
}


int main(int ac, char **av) {

  parseopts(ac, av);

  struct randstate rs;
  prand_init(&rs);

  gentables();

  uint64_t testedkeys = 0ULL;
  uint64_t stat[ENDROUND];
  for (int i = 0; i < 12; i++)
    stat[i] = 0;
  int stay = 0;
  int rerand = 0;
  time_t startTime = time(NULL);
  for (int c = 0; c < opts.count; c++) {
    for (int cc = 0; cc < 1000000; cc++) {
      testedkeys++;
      uint64_t key[2];
      uint8_t valid;
      int pres = 0;
      if (!stay) {
	valid = randkey(key);
	for (int i = 0; i < 4; i++)
	  if (valid & (1 << i))
	    pres = i;

	rk[opts.startround*4    ] = key[0] & 0xFFFFFFFFULL;
	rk[opts.startround*4 + 1] = (key[0] >> 32) & 0xFFFFFFFFULL;
	rk[opts.startround*4 + 2] = key[1] & 0xFFFFFFFFULL;
	rk[opts.startround*4 + 3] = (key[1] >> 32) & 0xFFFFFFFFULL;

	rk[opts.startround*4 + 4] = prand(&rs);
      } else {
	rk[opts.startround*4 + 4]++;
	stay--;
      }

      fillkey(opts.startround*4+5, opts.startround*4+8);
      int next = validateround(opts.startround+1, pres);

      if (next == -1)
	continue;

      int to = preservesto(opts.startround+2, next);
      stat[to]++;
      stay += 1000;
      if (stay > 100000)
	stay = 100000;
	

      if (to >= opts.printround)
	printkey(to);
      if (to >= opts.targetround)
	goto out;
    }

    if (opts.duration > 0) {
      time_t now = time(NULL); 
      if (now - startTime >= opts.duration)
	goto out;
    }
  }
out:
  if (!opts.printhex) {
    time_t total = time(NULL) - startTime;
    printf("\nTime: %d seconds\n", total);
    printf("Keys: %llu\n", testedkeys);
    printf("Rate: %llu keys/sec\n", (testedkeys+total/2)/total);
    printf("\nAchieved rounds:\n");
    for (int i = 5; i  < ENDROUND; i++)
      printf("%2d: %llu\n", i, stat[i]);
  }
}
