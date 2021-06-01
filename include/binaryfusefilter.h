#ifndef BINARYFUSEFILTER_H
#define BINARYFUSEFILTER_H
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
 * We start with a few utilities.
 ***/
static inline uint64_t binary_fusemurmur64(uint64_t h) {
  h ^= h >> 33;
  h *= UINT64_C(0xff51afd7ed558ccd);
  h ^= h >> 33;
  h *= UINT64_C(0xc4ceb9fe1a85ec53);
  h ^= h >> 33;
  return h;
}

static inline uint64_t binary_fusemix_split(uint64_t key, uint64_t seed) {
  return binary_fusemurmur64(key + seed);
}

static inline uint64_t binary_fuserotl64(uint64_t n, unsigned int c) {
  return (n << (c & 63)) | (n >> ((-c) & 63));
}

static inline uint32_t binary_fuse_reduce(uint32_t hash, uint32_t n) {
  // http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
  return (uint32_t)(((uint64_t)hash * n) >> 32);
}

static inline uint64_t binary_fusefingerprint(uint64_t hash) {
  return hash ^ (hash >> 32);
}

/**
 * We need a decent random number generator.
 **/

// returns random number, modifies the seed
static inline uint64_t binary_fuserng_splitmix64(uint64_t *seed) {
  uint64_t z = (*seed += UINT64_C(0x9E3779B97F4A7C15));
  z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
  z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
  return z ^ (z >> 31);
}

typedef struct binary_fuse8_s {
  uint64_t Seed;
  uint32_t SegmentLength; 
  uint32_t segmentLengthMask;
  uint32_t SegmentCount;
  uint32_t SegmentCountLength;
  uint8_t *fingerprints;
} binary_fuse8_t;
#ifdef _MSC_VER
// Windows programmers who target 32-bit platform may need help:
uint64_t binary_fuse_mulhi(uint64_t a, uint64_t b) {
  return __umulh(a, b);
}
#else 
uint64_t binary_fuse_mulhi(uint64_t a, uint64_t b) {
  return ((__uint128_t)a * b ) >> 64;
}
#endif

typedef struct binary_hashes_s {
  uint32_t h0;
  uint32_t h1;
  uint32_t h2;
} binary_hashes_t;

static binary_hashes_t binary_fuse_hash(uint64_t hash) {
   uint64_t hi = binary_fuse_mulhi(hash, filter->SegmentCountLength);
   uint32_t h0 = (uint32_t) hi;
   uint32_t h1 = h0 +  filter->SegmentLength;
   uint32_t h2 = h1 +  filter->SegmentLength;
   h1 ^= (uint32_t)(hash>>18) & filter.SegmentLengthMask;
   h2 ^= (uint32_t)(hash) & filter.SegmentLengthMask;
   return {h0, h1, h2};
}

// Report if the key is in the set, with false positive rate.
static inline bool binary_fuse8_contain(uint64_t key, const binary_fuse8_t *filter) {
  uint64_t hash = binary_fusemix_split(key, filter->Seed);
  uint8_t f = binary_fusefingerprint(hash);
  binary_hashes_t hashes = binary_fuse_hash(hash);	
  f ^= filter->Fingerprints[h0] ^ filter->Fingerprints[h1] ^ filter->Fingerprints[h2]
  return f == 0
}
// allocate enough capacity for a set containing up to 'size' elements
// caller is responsible to call fuse8_free(filter)
static inline bool binary_fuse8_allocate(uint32_t size, fuse8_t *filter) {
  size_t capacity = 1.0 / 0.879 * size;
  capacity = capacity / BINARY_FUSE_SLOTS * BINARY_FUSE_SLOTS;
  filter->fingerprints = (uint8_t *)malloc(capacity * sizeof(uint8_t));
  if (filter->fingerprints != NULL) {
    filter->segmentLength = capacity / BINARY_FUSE_SLOTS;
    return true;
  } else {
    return false;
  }
}

// report memory usage
static inline size_t fuse8_size_in_bytes(const fuse8_t *filter) {
  return BINARY_FUSE_SLOTS * filter->segmentLength * sizeof(uint8_t) + sizeof(fuse8_t);
}

// release memory
static inline void fuse8_free(fuse8_t *filter) {
  free(filter->fingerprints);
  filter->fingerprints = NULL;
  filter->segmentLength = 0;
}

struct binary_fusefuseset_s {
  uint64_t fusemask;
  uint32_t count;
};

typedef struct binary_fusefuseset_s binary_fusefuseset_t;

struct binary_fusehashes_s {
  uint64_t h;
  uint32_t h0;
  uint32_t h1;
  uint32_t h2;
};

typedef struct binary_fusehashes_s binary_fusehashes_t;

static inline binary_fusehashes_t fuse8_get_h0_h1_h2(uint64_t k, const fuse8_t *filter) {
  uint64_t hash = binary_fusemix_split(k, filter->seed);
  binary_fusehashes_t answer;
  answer.h = hash;
  uint32_t r0 = (uint32_t)hash;
  uint32_t r1 = (uint32_t)binary_fuserotl64(hash, 21);
  uint32_t r2 = (uint32_t)binary_fuserotl64(hash, 42);
  uint32_t r3 = (0xBF58476D1CE4E5B9 * hash) >> 32;
  uint32_t seg = binary_fuse_reduce(r0, BINARY_FUSE_SEGMENT_COUNT);
  answer.h0 = (seg + 0) * filter->segmentLength + binary_fuse_reduce(r1, filter->segmentLength);
  answer.h1 = (seg + 1) * filter->segmentLength + binary_fuse_reduce(r2, filter->segmentLength);
  answer.h2 = (seg + 2) * filter->segmentLength + binary_fuse_reduce(r3, filter->segmentLength);
  return answer;
}

struct binary_fuseh0h1h2_s {
  uint32_t h0;
  uint32_t h1;
  uint32_t h2;
};

typedef struct binary_fuseh0h1h2_s binary_fuseh0h1h2_t;

static inline binary_fuseh0h1h2_t fuse8_get_just_h0_h1_h2(uint64_t hash,
                                                  const fuse8_t *filter) {
  binary_fuseh0h1h2_t answer;
  uint32_t r0 = (uint32_t)hash;
  uint32_t r1 = (uint32_t)binary_fuserotl64(hash, 21);
  uint32_t r2 = (uint32_t)binary_fuserotl64(hash, 42);
  uint32_t r3 = (0xBF58476D1CE4E5B9 * hash) >> 32;
  uint32_t seg = binary_fuse_reduce(r0, BINARY_FUSE_SEGMENT_COUNT);
  answer.h0 = (seg + 0) * filter->segmentLength + binary_fuse_reduce(r1, filter->segmentLength);
  answer.h1 = (seg + 1) * filter->segmentLength + binary_fuse_reduce(r2, filter->segmentLength);
  answer.h2 = (seg + 2) * filter->segmentLength + binary_fuse_reduce(r3, filter->segmentLength);
  return answer;
}

struct binary_fusekeyindex_s {
  uint64_t hash;
  uint32_t index;
};

typedef struct binary_fusekeyindex_s binary_fusekeyindex_t;

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
  filter->seed = binary_fuserng_splitmix64(&rng_counter);
  size_t arrayLength = filter->segmentLength * BINARY_FUSE_SLOTS; // size of the backing array
  //size_t segmentLength = filter->segmentLength;
  binary_fusefuseset_t *sets =
      (binary_fusefuseset_t *)malloc(arrayLength * sizeof(binary_fusefuseset_t));

  binary_fusekeyindex_t *Q =
      (binary_fusekeyindex_t *)malloc(arrayLength * sizeof(binary_fusekeyindex_t));

  binary_fusekeyindex_t *stack =
      (binary_fusekeyindex_t *)malloc(size * sizeof(binary_fusekeyindex_t));

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


    memset(sets, 0, sizeof(binary_fusefuseset_t) * arrayLength);
    for (size_t i = 0; i < size; i++) {
      uint64_t key = keys[i];
      binary_fusehashes_t hs = fuse8_get_h0_h1_h2(key, filter);
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
      binary_fusekeyindex_t keyindex = Q[--Qsize];
      size_t index = keyindex.index;
      if (sets[index].count == 0)
        continue;  // not actually possible after the initial scan.
      // sets0[index].count = 0;
      uint64_t hash = keyindex.hash;
      binary_fuseh0h1h2_t hs = fuse8_get_just_h0_h1_h2(hash, filter);

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

    filter->seed = binary_fuserng_splitmix64(&rng_counter);
  }

  size_t stack_size = size;
  while (stack_size > 0) {
    binary_fusekeyindex_t ki = stack[--stack_size];
    binary_fuseh0h1h2_t hs = fuse8_get_just_h0_h1_h2(ki.hash, filter);
    uint8_t hsh = binary_fusefingerprint(ki.hash);
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
