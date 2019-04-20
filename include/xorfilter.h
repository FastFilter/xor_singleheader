#ifndef XORFILTER_H
#define XORFILTER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/**
 * We assume that you have a large set of 64-bit integers
 * and you want a data structure to do membership tests using
 * no more than ~8 or ~16 bits per key. If your initial set
 * is made of strings or other types, you first need to hash them
 * to a 64-bit integer.
 */

/**
 * We start with a few utilities.
 ***/
static inline uint64_t xor_murmur64(uint64_t h) {
  h ^= h >> 33;
  h *= UINT64_C(0xff51afd7ed558ccd);
  h ^= h >> 33;
  h *= UINT64_C(0xc4ceb9fe1a85ec53);
  h ^= h >> 33;
  return h;
}

static inline uint64_t xor_mix_split(uint64_t key, uint64_t seed) {
  return xor_murmur64(key + seed);
}

static inline uint64_t xor_rotl64(uint64_t n, unsigned int c) {
  return (n << (c & 63)) | (n >> ((-c) & 63));
}

static inline uint32_t xor_reduce(uint32_t hash, uint32_t n) {
  // http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
  return (uint32_t)(((uint64_t)hash * n) >> 32);
}

static inline uint64_t xor_fingerprint(uint64_t hash) {
  return hash ^ (hash >> 32);
}

/**
 * We need a decent random number generator.
 **/

// returns random number, modifies the seed
static inline uint64_t xor_rng_splitmix64(uint64_t *seed) {
  uint64_t z = (*seed += UINT64_C(0x9E3779B97F4A7C15));
  z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
  z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
  return z ^ (z >> 31);
}

/**
 * xor8 is the recommended default, no more than
 * a 0.3% false-positive probability.
 */
typedef struct xor8_s {
  uint64_t seed;
  uint64_t blockLength;
  uint8_t
      *fingerprints; // after xor8_allocate, will point to 3*blockLength values
} xor8_t;

// Report if the key is in the set, with false positive rate.
static inline bool xor8_contain(uint64_t key, const xor8_t *filter) {
  uint64_t hash = xor_mix_split(key, filter->seed);
  uint8_t f = xor_fingerprint(hash);
  uint32_t r0 = (uint32_t)hash;
  uint32_t r1 = (uint32_t)xor_rotl64(hash, 21);
  uint32_t r2 = (uint32_t)xor_rotl64(hash, 42);
  uint32_t h0 = xor_reduce(r0, filter->blockLength);
  uint32_t h1 = xor_reduce(r1, filter->blockLength) + filter->blockLength;
  uint32_t h2 = xor_reduce(r2, filter->blockLength) + 2 * filter->blockLength;
  f ^= filter->fingerprints[h0] ^ filter->fingerprints[h1] ^
       filter->fingerprints[h2];
  return f == 0;
}

typedef struct xor16_s {
  uint64_t seed;
  uint64_t blockLength;
  uint16_t
      *fingerprints; // after xor16_allocate, will point to 3*blockLength values
} xor16_t;

// Report if the key is in the set, with false positive rate.
static inline bool xor16_contain(uint64_t key, const xor16_t *filter) {
  uint64_t hash = xor_mix_split(key, filter->seed);
  uint16_t f = xor_fingerprint(hash);
  uint32_t r0 = (uint32_t)hash;
  uint32_t r1 = (uint32_t)xor_rotl64(hash, 21);
  uint32_t r2 = (uint32_t)xor_rotl64(hash, 42);
  uint32_t h0 = xor_reduce(r0, filter->blockLength);
  uint32_t h1 = xor_reduce(r1, filter->blockLength) + filter->blockLength;
  uint32_t h2 = xor_reduce(r2, filter->blockLength) + 2 * filter->blockLength;
  f ^= filter->fingerprints[h0] ^ filter->fingerprints[h1] ^
       filter->fingerprints[h2];
  return f == 0;
}

// allocate enough capacity for a set containing up to 'size' elements
// caller is responsible to call xor8_free(filter)
static inline bool xor8_allocate(uint32_t size, xor8_t *filter) {
  size_t capacity = 32 + 1.23 * size;
  capacity = capacity / 3 * 3;
  filter->fingerprints = (uint8_t *)malloc(capacity * sizeof(uint8_t));
  if (filter->fingerprints != NULL) {
    filter->blockLength = capacity / 3;
    return true;
  } else {
    return false;
  }
}

// allocate enough capacity for a set containing up to 'size' elements
// caller is responsible to call xor8_free(filter)
static inline bool xor16_allocate(size_t size, xor16_t *filter) {
  size_t capacity = 32 + 1.23 * size;
  filter->blockLength = capacity / 3;
  capacity = capacity / 3 * 3;
  filter->fingerprints = (uint16_t *)malloc(capacity * sizeof(uint16_t));
  if (filter->fingerprints != NULL) {
    filter->blockLength = capacity / 3;
    return true;
  } else {
    return false;
  }
}

// report memory usage
static inline size_t xor8_size_in_bytes(const xor8_t *filter) {
  return 3 * filter->blockLength * sizeof(uint8_t) + sizeof(xor8_t);
}

// report memory usage
static inline size_t xor16_size_in_bytes(const xor16_t *filter) {
  return 3 * filter->blockLength * sizeof(uint16_t) + sizeof(xor16_t);
}

// release memory
static inline void xor8_free(xor8_t *filter) {
  free(filter->fingerprints);
  filter->fingerprints = NULL;
  filter->blockLength = 0;
}

// release memory
static inline void xor16_free(xor16_t *filter) {
  free(filter->fingerprints);
  filter->fingerprints = NULL;
  filter->blockLength = 0;
}

struct xor_xorset_s {
  uint64_t xormask;
  uint64_t count;
};

typedef struct xor_xorset_s xor_xorset_t;

struct xor_hashes_s {
  uint64_t h;
  uint32_t h0;
  uint32_t h1;
  uint32_t h2;
};

typedef struct xor_hashes_s xor_hashes_t;

static inline xor_hashes_t xor8_get_h0_h1_h2(uint64_t k, const xor8_t *filter) {
  uint64_t hash = xor_mix_split(k, filter->seed);
  xor_hashes_t answer;
  answer.h = hash;
  uint32_t r0 = (uint32_t)hash;
  uint32_t r1 = (uint32_t)xor_rotl64(hash, 21);
  uint32_t r2 = (uint32_t)xor_rotl64(hash, 42);

  answer.h0 = xor_reduce(r0, filter->blockLength);
  answer.h1 = xor_reduce(r1, filter->blockLength) + filter->blockLength;
  answer.h2 = xor_reduce(r2, filter->blockLength) + 2 * filter->blockLength;
  return answer;
}

struct xor_h0h1h2_s {
  uint32_t h0;
  uint32_t h1;
  uint32_t h2;
};

typedef struct xor_h0h1h2_s xor_h0h1h2_t;

static inline xor_h0h1h2_t xor8_get_just_h0_h1_h2(uint64_t hash,
                                                  const xor8_t *filter) {
  xor_h0h1h2_t answer;
  uint32_t r0 = (uint32_t)hash;
  uint32_t r1 = (uint32_t)xor_rotl64(hash, 21);
  uint32_t r2 = (uint32_t)xor_rotl64(hash, 42);

  answer.h0 = xor_reduce(r0, filter->blockLength);
  answer.h1 = xor_reduce(r1, filter->blockLength) + filter->blockLength;
  answer.h2 = xor_reduce(r2, filter->blockLength) + 2 * filter->blockLength;
  return answer;
}
static inline uint32_t xor8_get_h0(uint64_t hash, const xor8_t *filter) {
  uint32_t r0 = (uint32_t)hash;
  return xor_reduce(r0, filter->blockLength);
}
static inline uint32_t xor8_get_h1(uint64_t hash, const xor8_t *filter) {
  uint32_t r1 = (uint32_t)xor_rotl64(hash, 21);
  return xor_reduce(r1, filter->blockLength) + filter->blockLength;
}
static inline uint32_t xor8_get_h2(uint64_t hash, const xor8_t *filter) {
  uint32_t r2 = (uint32_t)xor_rotl64(hash, 42);
  return xor_reduce(r2, filter->blockLength) + 2 * filter->blockLength;
}
static inline uint32_t xor16_get_h0(uint64_t hash, const xor16_t *filter) {
  uint32_t r0 = (uint32_t)hash;
  return xor_reduce(r0, filter->blockLength);
}
static inline uint32_t xor16_get_h1(uint64_t hash, const xor16_t *filter) {
  uint32_t r1 = (uint32_t)xor_rotl64(hash, 21);
  return xor_reduce(r1, filter->blockLength) + filter->blockLength;
}
static inline uint32_t xor16_get_h2(uint64_t hash, const xor16_t *filter) {
  uint32_t r2 = (uint32_t)xor_rotl64(hash, 42);
  return xor_reduce(r2, filter->blockLength) + 2 * filter->blockLength;
}
static inline xor_hashes_t xor16_get_h0_h1_h2(uint64_t k,
                                              const xor16_t *filter) {
  uint64_t hash = xor_mix_split(k, filter->seed);
  xor_hashes_t answer;
  answer.h = hash;
  uint32_t r0 = (uint32_t)hash;
  uint32_t r1 = (uint32_t)xor_rotl64(hash, 21);
  uint32_t r2 = (uint32_t)xor_rotl64(hash, 42);

  answer.h0 = xor_reduce(r0, filter->blockLength);
  answer.h1 = xor_reduce(r1, filter->blockLength) + filter->blockLength;
  answer.h2 = xor_reduce(r2, filter->blockLength) + 2 * filter->blockLength;
  return answer;
}

static inline xor_h0h1h2_t xor16_get_just_h0_h1_h2(uint64_t hash,
                                                   const xor16_t *filter) {
  xor_h0h1h2_t answer;
  uint32_t r0 = (uint32_t)hash;
  uint32_t r1 = (uint32_t)xor_rotl64(hash, 21);
  uint32_t r2 = (uint32_t)xor_rotl64(hash, 42);

  answer.h0 = xor_reduce(r0, filter->blockLength);
  answer.h1 = xor_reduce(r1, filter->blockLength) + filter->blockLength;
  answer.h2 = xor_reduce(r2, filter->blockLength) + 2 * filter->blockLength;
  return answer;
}

struct xor_keyindex_s {
  uint64_t hash;
  uint64_t index;
};

typedef struct xor_keyindex_s xor_keyindex_t;

//
// construct the filter, returns true on success, false on failure.
// most likely, a failure is due to too high a memory usage
// size is the number of keys
// the caller is responsable for calling xor8_allocate(size,filter) before
//
bool xor8_populate(const uint64_t *keys, size_t size, xor8_t *filter) {
  uint64_t rng_counter = 1;
  filter->seed = xor_rng_splitmix64(&rng_counter);
  size_t arrayLength = filter->blockLength * 3; // size of the backing array
  xor_xorset_t *sets =
      (xor_xorset_t *)malloc(arrayLength * sizeof(xor_xorset_t));
  xor_keyindex_t *Q =
      (xor_keyindex_t *)malloc(arrayLength * sizeof(xor_keyindex_t));
  xor_keyindex_t *Q0 = Q;
  xor_keyindex_t *Q1 = Q + filter->blockLength;
  xor_keyindex_t *Q2 = Q + 2 * filter->blockLength;
  xor_keyindex_t *stack =
      (xor_keyindex_t *)malloc(size * sizeof(xor_keyindex_t));

  if ((sets == NULL) || (Q == NULL) || (stack == NULL)) {
    free(sets);
    free(Q);
    free(stack);
    return false;
  }

  while (true) {
    memset(sets, 0, sizeof(xor_xorset_t) * arrayLength);
    for (size_t i = 0; i < size; i++) {
      uint64_t key = keys[i];
      xor_hashes_t hs = xor8_get_h0_h1_h2(key, filter);
      sets[hs.h0].xormask ^= hs.h;
      sets[hs.h0].count++;
      sets[hs.h1].xormask ^= hs.h;
      sets[hs.h1].count++;
      sets[hs.h2].xormask ^= hs.h;
      sets[hs.h2].count++;
    }
    // scan for values with a count of one
    size_t Q0size = 0, Q1size = 0, Q2size = 0;
    for (size_t i = 0; i < filter->blockLength; i++) {
      if (sets[i].count == 1) {
        Q0[Q0size].index = i;
        Q0[Q0size].hash = sets[i].xormask;
        Q0size++;
      }
    }
    for (size_t i = filter->blockLength; i < 2 * filter->blockLength; i++) {
      if (sets[i].count == 1) {
        Q1[Q1size].index = i;
        Q1[Q1size].hash = sets[i].xormask;
        Q1size++;
      }
    }
    for (size_t i = 2 * filter->blockLength; i < 3 * filter->blockLength; i++) {
      if (sets[i].count == 1) {
        Q2[Q2size].index = i;
        Q2[Q2size].hash = sets[i].xormask;
        Q2size++;
      }
    }
    size_t stack_size = 0;
    while (Q0size + Q1size + Q2size > 0) {
      while (Q0size > 0) {
        xor_keyindex_t keyindex = Q0[--Q0size];
        size_t index = keyindex.index;
        if (sets[index].count == 0)
          continue; // not actually possible after the initial scan.
        uint64_t hash = keyindex.hash;
        uint32_t h1 = xor8_get_h1(hash, filter);
        uint32_t h2 = xor8_get_h2(hash, filter);
        stack[stack_size] = keyindex;
        stack_size++;
        sets[h1].xormask ^= hash;
        sets[h1].count--;
        if (sets[h1].count == 1) {
          Q1[Q1size].index = h1;
          Q1[Q1size].hash = sets[h1].xormask;
          Q1size++;
        }
        sets[h2].xormask ^= hash;
        sets[h2].count--;
        if (sets[h2].count == 1) {
          Q2[Q2size].index = h2;
          Q2[Q2size].hash = sets[h2].xormask;
          Q2size++;
        }
      }
      while (Q1size > 0) {
        xor_keyindex_t keyindex = Q1[--Q1size];
        size_t index = keyindex.index;
        if (sets[index].count == 0)
          continue;
        uint64_t hash = keyindex.hash;
        uint32_t h0 = xor8_get_h0(hash, filter);
        uint32_t h2 = xor8_get_h2(hash, filter);
        stack[stack_size] = keyindex;
        stack_size++;
        sets[h0].xormask ^= hash;
        sets[h0].count--;
        if (sets[h0].count == 1) {
          Q0[Q0size].index = h0;
          Q0[Q0size].hash = sets[h0].xormask;
          Q0size++;
        }
        sets[h2].xormask ^= hash;
        sets[h2].count--;
        if (sets[h2].count == 1) {
          Q2[Q2size].index = h2;
          Q2[Q2size].hash = sets[h2].xormask;
          Q2size++;
        }
      }
      while (Q2size > 0) {
        xor_keyindex_t keyindex = Q2[--Q2size];
        size_t index = keyindex.index;
        if (sets[index].count == 0)
          continue;
        uint64_t hash = keyindex.hash;
        uint32_t h0 = xor8_get_h0(hash, filter);
        uint32_t h1 = xor8_get_h1(hash, filter);
        stack[stack_size] = keyindex;
        stack_size++;
        sets[h0].xormask ^= hash;
        sets[h0].count--;
        if (sets[h0].count == 1) {
          Q0[Q0size].index = h0;
          Q0[Q0size].hash = sets[h0].xormask;
          Q0size++;
        }
        sets[h1].xormask ^= hash;
        sets[h1].count--;
        if (sets[h1].count == 1) {
          Q1[Q1size].index = h1;
          Q1[Q1size].hash = sets[h1].xormask;
          Q1size++;
        }
      }
    }
    if (stack_size == size) {
      // success
      break;
    }
    // use a new random numbers
    filter->seed = xor_rng_splitmix64(&rng_counter);
  }
  size_t stack_size = size;
  while (stack_size > 0) {
    xor_keyindex_t ki = stack[--stack_size];
    xor_h0h1h2_t hashes = xor8_get_just_h0_h1_h2(ki.hash, filter);
    filter->fingerprints[ki.index] = 0;
    filter->fingerprints[ki.index] =
        xor_fingerprint(ki.hash) ^ filter->fingerprints[hashes.h0] ^
        filter->fingerprints[hashes.h1] ^ filter->fingerprints[hashes.h2];
  }
  free(sets);
  free(Q);
  free(stack);
  return true;
}

//
// construct the filter, returns true on success, false on failure.
// most likely, a failure is due to too high a memory usage
// size is the number of keys
// the caller is responsable for calling xor8_allocate(size,filter) before
//
bool xor16_populate(const uint64_t *keys, size_t size, xor16_t *filter) {
  uint64_t rng_counter = 1;
  filter->seed = xor_rng_splitmix64(&rng_counter);
  size_t arrayLength = filter->blockLength * 3; // size of the backing array
  xor_xorset_t *sets =
      (xor_xorset_t *)malloc(arrayLength * sizeof(xor_xorset_t));
  xor_keyindex_t *Q =
      (xor_keyindex_t *)malloc(arrayLength * sizeof(xor_keyindex_t));
  xor_keyindex_t *Q0 = Q;
  xor_keyindex_t *Q1 = Q + filter->blockLength;
  xor_keyindex_t *Q2 = Q + 2 * filter->blockLength;
  xor_keyindex_t *stack =
      (xor_keyindex_t *)malloc(size * sizeof(xor_keyindex_t));

  if ((sets == NULL) || (Q == NULL) || (stack == NULL)) {
    free(sets);
    free(Q);
    free(stack);
    return false;
  }

  while (true) {
    memset(sets, 0, sizeof(xor_xorset_t) * arrayLength);
    for (size_t i = 0; i < size; i++) {
      uint64_t key = keys[i];
      xor_hashes_t hs = xor16_get_h0_h1_h2(key, filter);
      sets[hs.h0].xormask ^= hs.h;
      sets[hs.h0].count++;
      sets[hs.h1].xormask ^= hs.h;
      sets[hs.h1].count++;
      sets[hs.h2].xormask ^= hs.h;
      sets[hs.h2].count++;
    }
    // scan for values with a count of one
    size_t Q0size = 0, Q1size = 0, Q2size = 0;
    for (size_t i = 0; i < filter->blockLength; i++) {
      if (sets[i].count == 1) {
        Q0[Q0size].index = i;
        Q0[Q0size].hash = sets[i].xormask;
        Q0size++;
      }
    }
    for (size_t i = filter->blockLength; i < 2 * filter->blockLength; i++) {
      if (sets[i].count == 1) {
        Q1[Q1size].index = i;
        Q1[Q1size].hash = sets[i].xormask;
        Q1size++;
      }
    }
    for (size_t i = 2 * filter->blockLength; i < 3 * filter->blockLength; i++) {
      if (sets[i].count == 1) {
        Q2[Q2size].index = i;
        Q2[Q2size].hash = sets[i].xormask;
        Q2size++;
      }
    }
    size_t stack_size = 0;
    while (Q0size + Q1size + Q2size > 0) {
      while (Q0size > 0) {
        xor_keyindex_t keyindex = Q0[--Q0size];
        size_t index = keyindex.index;
        if (sets[index].count == 0)
          continue; // not actually possible after the initial scan.
        uint64_t hash = keyindex.hash;
        uint32_t h1 = xor16_get_h1(hash, filter);
        uint32_t h2 = xor16_get_h2(hash, filter);
        stack[stack_size] = keyindex;
        stack_size++;
        sets[h1].xormask ^= hash;
        sets[h1].count--;
        if (sets[h1].count == 1) {
          Q1[Q1size].index = h1;
          Q1[Q1size].hash = sets[h1].xormask;
          Q1size++;
        }
        sets[h2].xormask ^= hash;
        sets[h2].count--;
        if (sets[h2].count == 1) {
          Q2[Q2size].index = h2;
          Q2[Q2size].hash = sets[h2].xormask;
          Q2size++;
        }
      }
      while (Q1size > 0) {
        xor_keyindex_t keyindex = Q1[--Q1size];
        size_t index = keyindex.index;
        if (sets[index].count == 0)
          continue;
        uint64_t hash = keyindex.hash;
        uint32_t h0 = xor16_get_h0(hash, filter);
        uint32_t h2 = xor16_get_h2(hash, filter);
        stack[stack_size] = keyindex;
        stack_size++;
        sets[h0].xormask ^= hash;
        sets[h0].count--;
        if (sets[h0].count == 1) {
          Q0[Q0size].index = h0;
          Q0[Q0size].hash = sets[h0].xormask;
          Q0size++;
        }
        sets[h2].xormask ^= hash;
        sets[h2].count--;
        if (sets[h2].count == 1) {
          Q2[Q2size].index = h2;
          Q2[Q2size].hash = sets[h2].xormask;
          Q2size++;
        }
      }
      while (Q2size > 0) {
        xor_keyindex_t keyindex = Q2[--Q2size];
        size_t index = keyindex.index;
        if (sets[index].count == 0)
          continue;
        uint64_t hash = keyindex.hash;
        uint32_t h0 = xor16_get_h0(hash, filter);
        uint32_t h1 = xor16_get_h1(hash, filter);
        stack[stack_size] = keyindex;
        stack_size++;
        sets[h0].xormask ^= hash;
        sets[h0].count--;
        if (sets[h0].count == 1) {
          Q0[Q0size].index = h0;
          Q0[Q0size].hash = sets[h0].xormask;
          Q0size++;
        }
        sets[h1].xormask ^= hash;
        sets[h1].count--;
        if (sets[h1].count == 1) {
          Q1[Q1size].index = h1;
          Q1[Q1size].hash = sets[h1].xormask;
          Q1size++;
        }
      }
    }
    if (stack_size == size) {
      // success
      break;
    }
    // use a new random numbers
    filter->seed = xor_rng_splitmix64(&rng_counter);
  }
  size_t stack_size = size;
  while (stack_size > 0) {
    xor_keyindex_t ki = stack[--stack_size];
    xor_h0h1h2_t hashes = xor16_get_just_h0_h1_h2(ki.hash, filter);
    filter->fingerprints[ki.index] = 0;
    filter->fingerprints[ki.index] =
        xor_fingerprint(ki.hash) ^ filter->fingerprints[hashes.h0] ^
        filter->fingerprints[hashes.h1] ^ filter->fingerprints[hashes.h2];
  }
  free(sets);
  free(Q);
  free(stack);
  return true;
}

#endif
