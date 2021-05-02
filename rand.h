#ifndef __RAND_H__
#define __RAND_H__ 1


#define RANDRESEED 10000

struct randstate {
  uint64_t s;
  int c;
};


static inline uint64_t rdrand64(void) {
  uint64_t r;
  asm __volatile__ ("rdrand %0":"=r" (r));
  return r;
}


static inline void prand_init(struct randstate *st) {
  st->s = rdrand64();
  st->c = RANDRESEED;
}


static inline uint64_t prand(struct randstate *state)
{
	uint64_t x = state->s;
	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	if (state->c-- < 0) {
	  x ^= rdrand64();
	  state->c = RANDRESEED;
	}
	return state->s = x;
}



#endif // __RAND_H__
