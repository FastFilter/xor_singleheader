#ifndef FUSEFILTER_H
#define FUSEFILTER_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef XOR_MAX_ITERATIONS
#define XOR_MAX_ITERATIONS 100 // probabillity of success should always be > 0.5 so 100 iterations is highly unlikely
#endif 

/**
 * Dietzfelbinger & Walzer's fuse filters,
 * described in "Dense Peelable Random Uniform Hypergraphs",
 * https://arxiv.org/abs/1907.04749, can accomodate fill factors up to
 * 87.9% full, rather than 1 / 1.23 = 81.3%. In the 8-bit case,
 * This reduces the memory usage from 9.84 bits per entry to 9.1 bits.
 */
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
static inline uint64_t fuse_murmur64(uint64_t h) {
  h ^= h >> 33;
  h *= UINT64_C(0xff51afd7ed558ccd);
  h ^= h >> 33;
  h *= UINT64_C(0xc4ceb9fe1a85ec53);
  h ^= h >> 33;
  return h;
}

static inline uint64_t fuse_mix_split(uint64_t key, uint64_t seed) {
  return fuse_murmur64(key + seed);
}

static inline uint64_t fuse_rotl64(uint64_t n, unsigned int c) {
  return (n << (c & 63)) | (n >> ((-c) & 63));
}

static inline uint32_t fuse_reduce(uint32_t hash, uint32_t n) {
  // http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
  return (uint32_t)(((uint64_t)hash * n) >> 32);
}

static inline uint64_t fuse_fingerprint(uint64_t hash) {
  return hash ^ (hash >> 32);
}

/**
 * We need a decent random number generator.
 **/

// returns random number, modifies the seed
static inline uint64_t fuse_rng_splitmix64(uint64_t *seed) {
  uint64_t z = (*seed += UINT64_C(0x9E3779B97F4A7C15));
  z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
  z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
  return z ^ (z >> 31);
}

#define FUSE_ARITY 3
#define FUSE_SEGMENT_COUNT 100
#define FUSE_SLOTS (FUSE_SEGMENT_COUNT + FUSE_ARITY - 1)

/**
 * fuse8 is the recommended default, no more than
 * a 0.3% false-positive probability.
 */
typedef struct fuse8_s {
  uint64_t seed;
  uint64_t segmentLength; // = slotCount  / FUSE_SLOTS
  uint8_t
      *fingerprints; // after fuse8_allocate, will point to 3*segmentLength values
} fuse8_t;

// Report if the key is in the set, with false positive rate.
static inline bool fuse8_contain(uint64_t key, const fuse8_t *filter) {
    uint64_t hash = fuse_mix_split(key, filter->seed);
  uint8_t f = fuse_fingerprint(hash);
  uint32_t r0 = (uint32_t)hash;
  uint32_t r1 = (uint32_t)fuse_rotl64(hash, 21);
  uint32_t r2 = (uint32_t)fuse_rotl64(hash, 42);
  uint32_t r3 = (0xBF58476D1CE4E5B9 * hash) >> 32;
  uint32_t seg = fuse_reduce(r0, FUSE_SEGMENT_COUNT);
  uint32_t h0 = (seg + 0) * filter->segmentLength + fuse_reduce(r1, filter->segmentLength);
  uint32_t h1 = (seg + 1) * filter->segmentLength + fuse_reduce(r2, filter->segmentLength);
  uint32_t h2 = (seg + 2) * filter->segmentLength + fuse_reduce(r3, filter->segmentLength);
  return f == (filter->fingerprints[h0] ^ filter->fingerprints[h1] ^
       filter->fingerprints[h2]);
}

// allocate enough capacity for a set containing up to 'size' elements
// caller is responsible to call fuse8_free(filter)
static inline bool fuse8_allocate(uint32_t size, fuse8_t *filter) {
  size_t capacity = 1.0 / 0.879 * size;
  capacity = capacity / FUSE_SLOTS * FUSE_SLOTS;
  filter->fingerprints = (uint8_t *)malloc(capacity * sizeof(uint8_t));
  if (filter->fingerprints != NULL) {
    filter->segmentLength = capacity / FUSE_SLOTS;
    return true;
  } else {
    return false;
  }
}

// report memory usage
static inline size_t fuse8_size_in_bytes(const fuse8_t *filter) {
  return FUSE_SLOTS * filter->segmentLength * sizeof(uint8_t) + sizeof(fuse8_t);
}

// release memory
static inline void fuse8_free(fuse8_t *filter) {
  free(filter->fingerprints);
  filter->fingerprints = NULL;
  filter->segmentLength = 0;
}

struct fuse_fuseset_s {
  uint64_t fusemask;
  uint32_t count;
};

typedef struct fuse_fuseset_s fuse_fuseset_t;

struct fuse_hashes_s {
  uint64_t h;
  uint32_t h0;
  uint32_t h1;
  uint32_t h2;
};

typedef struct fuse_hashes_s fuse_hashes_t;

static inline fuse_hashes_t fuse8_get_h0_h1_h2(uint64_t k, const fuse8_t *filter) {
  uint64_t hash = fuse_mix_split(k, filter->seed);
  fuse_hashes_t answer;
  answer.h = hash;
  uint32_t r0 = (uint32_t)hash;
  uint32_t r1 = (uint32_t)fuse_rotl64(hash, 21);
  uint32_t r2 = (uint32_t)fuse_rotl64(hash, 42);
  uint32_t r3 = (0xBF58476D1CE4E5B9 * hash) >> 32;
  uint32_t seg = fuse_reduce(r0, FUSE_SEGMENT_COUNT);
  answer.h0 = (seg + 0) * filter->segmentLength + fuse_reduce(r1, filter->segmentLength);
  answer.h1 = (seg + 1) * filter->segmentLength + fuse_reduce(r2, filter->segmentLength);
  answer.h2 = (seg + 2) * filter->segmentLength + fuse_reduce(r3, filter->segmentLength);
  return answer;
}

struct fuse_h0h1h2_s {
  uint32_t h0;
  uint32_t h1;
  uint32_t h2;
};

typedef struct fuse_h0h1h2_s fuse_h0h1h2_t;

static inline fuse_h0h1h2_t fuse8_get_just_h0_h1_h2(uint64_t hash,
                                                  const fuse8_t *filter) {
  fuse_h0h1h2_t answer;
  uint32_t r0 = (uint32_t)hash;
  uint32_t r1 = (uint32_t)fuse_rotl64(hash, 21);
  uint32_t r2 = (uint32_t)fuse_rotl64(hash, 42);
  uint32_t r3 = (0xBF58476D1CE4E5B9 * hash) >> 32;
  uint32_t seg = fuse_reduce(r0, FUSE_SEGMENT_COUNT);
  answer.h0 = (seg + 0) * filter->segmentLength + fuse_reduce(r1, filter->segmentLength);
  answer.h1 = (seg + 1) * filter->segmentLength + fuse_reduce(r2, filter->segmentLength);
  answer.h2 = (seg + 2) * filter->segmentLength + fuse_reduce(r3, filter->segmentLength);
  return answer;
}

struct fuse_keyindex_s {
  uint64_t hash;
  uint32_t index;
};

typedef struct fuse_keyindex_s fuse_keyindex_t;

//
// construct the filter, returns true on success, false on failure.
// most likely, a failure is due to too high a memory usage
// size is the number of keys
// The caller is responsable for calling fuse8_allocate(size,filter) before.
// The caller is responsible to ensure that there are no duplicated keys.
// The inner loop will run up to XOR_MAX_ITERATIONS times (default on 100),
// it should never fail, except if there are duplicated keys. If it fails,
// a return value of false is provided.
//
bool fuse8_populate(const uint64_t *keys, uint32_t size, fuse8_t *filter) {
  uint64_t rng_counter = 1;
  filter->seed = fuse_rng_splitmix64(&rng_counter);
  size_t arrayLength = filter->segmentLength * FUSE_SLOTS; // size of the backing array
  //size_t segmentLength = filter->segmentLength;
  fuse_fuseset_t *sets =
      (fuse_fuseset_t *)malloc(arrayLength * sizeof(fuse_fuseset_t));

  fuse_keyindex_t *Q =
      (fuse_keyindex_t *)malloc(arrayLength * sizeof(fuse_keyindex_t));

  fuse_keyindex_t *stack =
      (fuse_keyindex_t *)malloc(size * sizeof(fuse_keyindex_t));

  if ((sets == NULL) || (Q == NULL) || (stack == NULL)) {
    free(sets);
    free(Q);
    free(stack);
    return false;
  }

  for (int loop = 0; true; ++loop) {
    if(loop + 1 > XOR_MAX_ITERATIONS) {
      fprintf(stderr, "Too many iterations. Are all your keys unique?");
      free(sets);
      free(Q);
      free(stack);
      return false;
    }


    memset(sets, 0, sizeof(fuse_fuseset_t) * arrayLength);
    for (size_t i = 0; i < size; i++) {
      uint64_t key = keys[i];
      fuse_hashes_t hs = fuse8_get_h0_h1_h2(key, filter);
      sets[hs.h0].fusemask ^= hs.h;
      sets[hs.h0].count++;
      sets[hs.h1].fusemask ^= hs.h;
      sets[hs.h1].count++;
      sets[hs.h2].fusemask ^= hs.h;
      sets[hs.h2].count++;
    }
    // todo: the flush should be sync with the detection that follows
    // scan for values with a count of one
    size_t Qsize = 0;
    for (size_t i = 0; i < arrayLength; i++) {
      if (sets[i].count == 1) {
        Q[Qsize].index = i;
        Q[Qsize].hash = sets[i].fusemask;
        Qsize++;
      }
    }

    size_t stack_size = 0;
    while (Qsize > 0) {
      fuse_keyindex_t keyindex = Q[--Qsize];
      size_t index = keyindex.index;
      if (sets[index].count == 0)
        continue;  // not actually possible after the initial scan.
      // sets0[index].count = 0;
      uint64_t hash = keyindex.hash;
      fuse_h0h1h2_t hs = fuse8_get_just_h0_h1_h2(hash, filter);

      stack[stack_size] = keyindex;
      stack_size++;

      //if (hs.h0 != index) {
        sets[hs.h0].fusemask ^= hash;
        sets[hs.h0].count--;
        if (sets[hs.h0].count == 1) {
          Q[Qsize].index = hs.h0;
          Q[Qsize].hash = sets[hs.h0].fusemask;
          Qsize++;
        }
        //}

        //if (hs.h1 != index) {
        sets[hs.h1].fusemask ^= hash;
        sets[hs.h1].count--;
        if (sets[hs.h1].count == 1) {
          Q[Qsize].index = hs.h1;
          Q[Qsize].hash = sets[hs.h1].fusemask;
          Qsize++;
        }
        //}

        //if (hs.h2 != index) {
        sets[hs.h2].fusemask ^= hash;
        sets[hs.h2].count--;
        if (sets[hs.h2].count == 1) {
          Q[Qsize].index = hs.h2;
          Q[Qsize].hash = sets[hs.h2].fusemask;
          Qsize++;
        }
        //}
    }

    if (stack_size == size) {
      // success
      break;
    }

    filter->seed = fuse_rng_splitmix64(&rng_counter);
  }

  size_t stack_size = size;
  while (stack_size > 0) {
    fuse_keyindex_t ki = stack[--stack_size];
    fuse_h0h1h2_t hs = fuse8_get_just_h0_h1_h2(ki.hash, filter);
    uint8_t hsh = fuse_fingerprint(ki.hash);
    if(ki.index == hs.h0) {
      hsh ^= filter->fingerprints[hs.h1] ^ filter->fingerprints[hs.h2];
    } else if(ki.index == hs.h1) {
      hsh ^= filter->fingerprints[hs.h0] ^ filter->fingerprints[hs.h2];
    } else {
      hsh ^= filter->fingerprints[hs.h0] ^ filter->fingerprints[hs.h1];
    }
    filter->fingerprints[ki.index] = hsh;
  }

  free(sets);
  free(Q);
  free(stack);
  return true;
}

#endif
