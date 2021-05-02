#ifndef __PERM_H__
#define __PERM_H__ 1


uint32_t keytoperm(uint64_t key);
uint64_t permtokey(uint32_t perm);

uint8_t randkey(uint64_t key[2]);


#endif // __PERM_H__
