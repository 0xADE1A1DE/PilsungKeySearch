#ifndef __TABLES_H__
#define __TABLES_H__ 1

/*
 * This file defines structures and macros for handling the "shift rows" permutation in 
 * Pilsung.
 * Specifically, Round Key RK_i determines the permutation used in round i-1.  The round
 * key is divided into two halves low (bytes 0-7) and high (bytes 8-15). The low half
 * decides the row that each state byte maps to.  The high half only distributes bytes
 * inside the rows.
 *
 * The tables store cached properties of permutation-ids.  Function to convert 64-bit
 * key-halves to perm-ids and vice versa are provided elsewhere.
 */


#define NPERMS (36*36*256)

struct tables {
  // The AES SBox
  uint8_t sbox[256];

  // Quickly calculates the mod 6 required for converting key to permid;
  uint8_t mod6[256*256];

  // There are only 24 valid positions for preservd colums. Bits here show if the high
  // permid has at least one column with these values.
  uint64_t valid34[NPERMS/64];

  // Non-zero if the low perm causes some column to be preserved, i.e. if preserves is true
  // for at least one column.
  uint8_t preservesany[36*36];


  // Bit (perm % 64) of preserves[col][perm/64] is set if the low perm can preserve 
  // column col, i.e. maps it to the some column.  
  // Whether a key actually preserves the column depends on the high half and is
  // not captured here.
  uint64_t preserves[4][NPERMS/64];

  // If low perm preserves column col, map12[col][perm] is a signature of where perm takes
  // the members of column col.  (maps12[col][perm] >> (row*2)) & 0x03 is the column number
  // that perm maps an entry of column col in row row.  map34 needs to organise these in 
  // the same column for preserving a column
  uint8_t map12[4][NPERMS];

  // Second half of permutation calculation: map34[col][perm] stores the columns from
  // which the four elements in col arrive.  In particular, if the low permutation perml
  // preserves column col1 and  map12[col1][perml] == map34[col2][permh], the permutation
  // perml.permh preserves col1 and maps it to col2.
  uint8_t map34[4][NPERMS];
};

extern struct tables *tables;

#define CANPRESERVEANY(perm) (tables->preservesany[LEVEL1(perm)])
#define CANPRESERVECOL(perm, column) (CANPRESERVEANY(perm) & (1 << (column)))
#define PRESERVES(permid, column) (tables->preserves[(column)][(permid)>>6] & (1ULL<<((permid) & 0x3f)))
#define MAP12(permid, column) (tables->map12[(column)][(permid)])
#define MAP34(permid, column) (tables->map34[(column)][(permid)])

#define VALID34(permid) (tables->valid34[(permid)>>6] & (1ULL<<((permid) & 0x3f)))

#define LEVEL1(perm) ((perm)>>8)
#define LEVEL2(perm) ((perm)&255)


#define SBOX(v) (tables->sbox[v])


void gentables();


#endif // __TABLES_H__
