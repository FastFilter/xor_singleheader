#ifndef BINARYFUSEFILTER_H
#define BINARYFUSEFILTER_H
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef XOR_MAX_ITERATIONS
// probability of success should always be > 0.5 so 100 iterations is highly unlikely
#define XOR_MAX_ITERATIONS 100 
#endif

static int binary_fuse_cmpfunc(const void * a, const void * b) {
  return (int)( *(const uint64_t*)a - *(const uint64_t*)b );
}

static size_t binary_fuse_sort_and_remove_dup(uint64_t* keys, size_t length) {
  qsort(keys, length, sizeof(uint64_t), binary_fuse_cmpfunc);
  size_t j = 1;
  for(size_t i = 1; i < length; i++) {
    if(keys[i] != keys[i-1]) {
      keys[j] = keys[i];
      j++;
    }
  }
  return j;
}

/**
 * We start with a few utilities.
 ***/
static inline uint64_t binary_fuse_murmur64(uint64_t h) {
  h ^= h >> 33U;
  h *= UINT64_C(0xff51afd7ed558ccd);
  h ^= h >> 33U;
  h *= UINT64_C(0xc4ceb9fe1a85ec53);
  h ^= h >> 33U;
  return h;
}
static inline uint64_t binary_fuse_mix_split(uint64_t key, uint64_t seed) {
  return binary_fuse_murmur64(key + seed);
}
static inline uint64_t binary_fuse_rotl64(uint64_t n, unsigned int c) {
  return (n << (c & 63U)) | (n >> ((-c) & 63U));
}
static inline uint32_t binary_fuse_reduce(uint32_t hash, uint32_t n) {
  // http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
  return (uint32_t)(((uint64_t)hash * n) >> 32U);
}
static inline uint8_t binary_fuse8_fingerprint(uint64_t hash) {
  return (uint8_t)(hash ^ (hash >> 32U));
}

/**
 * We need a decent random number generator.
 **/

// returns random number, modifies the seed
static inline uint64_t binary_fuse_rng_splitmix64(uint64_t *seed) {
  uint64_t z = (*seed += UINT64_C(0x9E3779B97F4A7C15));
  z = (z ^ (z >> 30U)) * UINT64_C(0xBF58476D1CE4E5B9);
  z = (z ^ (z >> 27U)) * UINT64_C(0x94D049BB133111EB);
  return z ^ (z >> 31U);
}

typedef struct binary_fuse8_s {
  uint64_t Seed;
  uint32_t Size;
  uint32_t SegmentLength;
  uint32_t SegmentLengthMask;
  uint32_t SegmentCount;
  uint32_t SegmentCountLength;
  uint32_t ArrayLength;
  uint8_t *Fingerprints;
} binary_fuse8_t;

// #ifdefs adapted from:
//  https://stackoverflow.com/a/50958815
#ifdef __SIZEOF_INT128__  // compilers supporting __uint128, e.g., gcc, clang
static inline uint64_t binary_fuse_mulhi(uint64_t a, uint64_t b) {
  return (uint64_t)(((__uint128_t)a * b) >> 64U);
}
#elif defined(_M_X64) || defined(_MARM64)   // MSVC
static inline uint64_t binary_fuse_mulhi(uint64_t a, uint64_t b) {
  return __umulh(a, b);
}
#elif defined(_M_IA64)  // also MSVC
static inline uint64_t binary_fuse_mulhi(uint64_t a, uint64_t b) {
  unsigned __int64 hi;
  (void) _umul128(a, b, &hi);
  return hi;
}
#else  // portable implementation using uint64_t
static inline uint64_t binary_fuse_mulhi(uint64_t a, uint64_t b) {
  // Adapted from:
  //  https://stackoverflow.com/a/51587262

  /*
        This is implementing schoolbook multiplication:

                a1 a0
        X       b1 b0
        -------------
                   00  LOW PART
        -------------
                00
             10 10     MIDDLE PART
        +       01
        -------------
             01
        + 11 11        HIGH PART
        -------------
  */

  const uint64_t a0 = (uint32_t) a;
  const uint64_t a1 = a >> 32;
  const uint64_t b0 = (uint32_t) b;
  const uint64_t b1 = b >> 32;
  const uint64_t p11 = a1 * b1;
  const uint64_t p01 = a0 * b1;
  const uint64_t p10 = a1 * b0;
  const uint64_t p00 = a0 * b0;

  // 64-bit product + two 32-bit values
  const uint64_t middle = p10 + (p00 >> 32) + (uint32_t) p01;

  /*
    Proof that 64-bit products can accumulate two more 32-bit values
    without overflowing:

    Max 32-bit value is 2^32 - 1.
    PSum = (2^32-1) * (2^32-1) + (2^32-1) + (2^32-1)
         = 2^64 - 2^32 - 2^32 + 1 + 2^32 - 1 + 2^32 - 1
         = 2^64 - 1
    Therefore the high half below cannot overflow regardless of input.
  */

  // high half
  return p11 + (middle >> 32) + (p01 >> 32);

  // low half (which we don't care about, but here it is)
  // (middle << 32) | (uint32_t) p00;
}
#endif

typedef struct binary_hashes_s {
  uint32_t h0;
  uint32_t h1;
  uint32_t h2;
} binary_hashes_t;

static inline binary_hashes_t binary_fuse8_hash_batch(uint64_t hash,
                                        const binary_fuse8_t *filter) {
  uint64_t hi = binary_fuse_mulhi(hash, filter->SegmentCountLength);
  binary_hashes_t ans;
  ans.h0 = (uint32_t)hi;
  ans.h1 = ans.h0 + filter->SegmentLength;
  ans.h2 = ans.h1 + filter->SegmentLength;
  ans.h1 ^= (uint32_t)(hash >> 18U) & filter->SegmentLengthMask;
  ans.h2 ^= (uint32_t)(hash)&filter->SegmentLengthMask;
  return ans;
}

static inline uint32_t binary_fuse8_hash(uint64_t index, uint64_t hash,
                                        const binary_fuse8_t *filter) {
    uint64_t h = binary_fuse_mulhi(hash, filter->SegmentCountLength);
    h += index * filter->SegmentLength;
    // keep the lower 36 bits
    uint64_t hh = hash & ((1ULL << 36U) - 1);
    // index 0: right shift by 36; index 1: right shift by 18; index 2: no shift
    h ^= (size_t)((hh >> (36 - 18 * index)) & filter->SegmentLengthMask);
    return (uint32_t)h;
}

// Report if the key is in the set, with false positive rate.
static inline bool binary_fuse8_contain(uint64_t key,
                                        const binary_fuse8_t *filter) {
  uint64_t hash = binary_fuse_mix_split(key, filter->Seed);
  uint8_t f = binary_fuse8_fingerprint(hash);
  binary_hashes_t hashes = binary_fuse8_hash_batch(hash, filter);
  f ^= (uint32_t)filter->Fingerprints[hashes.h0] ^
       filter->Fingerprints[hashes.h1] ^
       filter->Fingerprints[hashes.h2];
  return f == 0;
}

static inline uint32_t binary_fuse_calculate_segment_length(uint32_t arity,
                                                             uint32_t size) {
  // These parameters are very sensitive. Replacing 'floor' by 'round' can
  // substantially affect the construction time.
  if (arity == 3) {
    return ((uint32_t)1) << (unsigned)(floor(log((double)(size)) / log(3.33) + 2.25));
  }
  if (arity == 4) {
    return ((uint32_t)1) << (unsigned)(floor(log((double)(size)) / log(2.91) - 0.5));
  }
  return 65536;
}

static inline double binary_fuse_max(double a, double b) {
  if (a < b) {
    return b;
  }
  return a;
}

static inline double binary_fuse_calculate_size_factor(uint32_t arity,
                                                        uint32_t size) {
  if (arity == 3) {
    return binary_fuse_max(1.125, 0.875 + 0.25 * log(1000000.0) / log((double)size));
  }
  if (arity == 4) {
    return binary_fuse_max(1.075, 0.77 + 0.305 * log(600000.0) / log((double)size));
  }
  return 2.0;
}

// allocate enough capacity for a set containing up to 'size' elements
// caller is responsible to call binary_fuse8_free(filter)
// size should be at least 2.
static inline bool binary_fuse8_allocate(uint32_t size,
                                         binary_fuse8_t *filter) {
  uint32_t arity = 3;
  filter->Size = size;
  filter->SegmentLength = size == 0 ? 4 : binary_fuse_calculate_segment_length(arity, size);
  if (filter->SegmentLength > 262144) {
    filter->SegmentLength = 262144;
  }
  filter->SegmentLengthMask = filter->SegmentLength - 1;
  double sizeFactor = size <= 1 ? 0 : binary_fuse_calculate_size_factor(arity, size);
  uint32_t capacity = size <= 1 ? 0 : (uint32_t)(round((double)size * sizeFactor));
  uint32_t initSegmentCount =
      (capacity + filter->SegmentLength - 1) / filter->SegmentLength -
      (arity - 1);
  filter->ArrayLength = (initSegmentCount + arity - 1) * filter->SegmentLength;
  filter->SegmentCount =
      (filter->ArrayLength + filter->SegmentLength - 1) / filter->SegmentLength;
  if (filter->SegmentCount <= arity - 1) {
    filter->SegmentCount = 1;
  } else {
    filter->SegmentCount = filter->SegmentCount - (arity - 1);
  }
  filter->ArrayLength =
      (filter->SegmentCount + arity - 1) * filter->SegmentLength;
  filter->SegmentCountLength = filter->SegmentCount * filter->SegmentLength;
  filter->Fingerprints =
      (uint8_t *)calloc(filter->ArrayLength, sizeof(uint8_t));
  return filter->Fingerprints != NULL;
}

// report memory usage
static inline size_t binary_fuse8_size_in_bytes(const binary_fuse8_t *filter) {
  return filter->ArrayLength * sizeof(uint8_t) + sizeof(binary_fuse8_t);
}

// release memory
static inline void binary_fuse8_free(binary_fuse8_t *filter) {
  free(filter->Fingerprints);
  filter->Fingerprints = NULL;
  filter->Seed = 0;
  filter->Size = 0;
  filter->SegmentLength = 0;
  filter->SegmentLengthMask = 0;
  filter->SegmentCount = 0;
  filter->SegmentCountLength = 0;
  filter->ArrayLength = 0;
}

static inline uint8_t binary_fuse_mod3(uint8_t x) {
    return x > 2 ? x - 3 : x;
}

// Construct the filter, returns true on success, false on failure.
// The algorithm fails when there is insufficient memory.
// The caller is responsable for calling binary_fuse8_allocate(size,filter)
// before. For best performance, the caller should ensure that there are not too
// many duplicated keys.
static inline bool binary_fuse8_populate(uint64_t *keys, uint32_t size,
                           binary_fuse8_t *filter) {
  if (size != filter->Size) {
    return false;
  }

  uint64_t rng_counter = 0x726b2b9d438b9d4d;
  filter->Seed = binary_fuse_rng_splitmix64(&rng_counter);
  uint64_t *reverseOrder = (uint64_t *)calloc((size + 1), sizeof(uint64_t));
  uint32_t capacity = filter->ArrayLength;
  uint32_t *alone = (uint32_t *)malloc(capacity * sizeof(uint32_t));
  uint8_t *t2count = (uint8_t *)calloc(capacity, sizeof(uint8_t));
  uint8_t *reverseH = (uint8_t *)malloc(size * sizeof(uint8_t));
  uint64_t *t2hash = (uint64_t *)calloc(capacity, sizeof(uint64_t));

  uint32_t blockBits = 1;
  while (((uint32_t)1 << blockBits) < filter->SegmentCount) {
    blockBits += 1;
  }
  uint32_t block = ((uint32_t)1 << blockBits);
  uint32_t *startPos = (uint32_t *)malloc((1U << blockBits) * sizeof(uint32_t));
  uint32_t h012[5];

  if ((alone == NULL) || (t2count == NULL) || (reverseH == NULL) ||
      (t2hash == NULL) || (reverseOrder == NULL) || (startPos == NULL)) {
    free(alone);
    free(t2count);
    free(reverseH);
    free(t2hash);
    free(reverseOrder);
    free(startPos);
    return false;
  }
  reverseOrder[size] = 1;
  for (int loop = 0; true; ++loop) {
    if (loop + 1 > XOR_MAX_ITERATIONS) {
      // The probability of this happening is lower than the
      // the cosmic-ray probability (i.e., a cosmic ray corrupts your system)
      memset(filter->Fingerprints, 0xFF, filter->ArrayLength);
      free(alone);
      free(t2count);
      free(reverseH);
      free(t2hash);
      free(reverseOrder);
      free(startPos);
      return false;
    }

    for (uint32_t i = 0; i < block; i++) {
      // important : i * size would overflow as a 32-bit number in some
      // cases.
      startPos[i] = (uint32_t)((uint64_t)i * size) >> blockBits;
    }

    uint64_t maskblock = block - 1;
    for (uint32_t i = 0; i < size; i++) {
      uint64_t hash = binary_fuse_murmur64(keys[i] + filter->Seed);
      uint64_t segment_index = hash >> (64 - blockBits);
      while (reverseOrder[startPos[segment_index]] != 0) {
        segment_index++;
        segment_index &= maskblock;
      }
      reverseOrder[startPos[segment_index]] = hash;
      startPos[segment_index]++;
    }
    int error = 0;
    uint32_t duplicates = 0;
    for (uint32_t i = 0; i < size; i++) {
      uint64_t hash = reverseOrder[i];
      uint32_t h0 = binary_fuse8_hash(0, hash, filter);
      t2count[h0] += 4;
      t2hash[h0] ^= hash;
      uint32_t h1= binary_fuse8_hash(1, hash, filter);
      t2count[h1] += 4;
      t2count[h1] ^= 1U;
      t2hash[h1] ^= hash;
      uint32_t h2 = binary_fuse8_hash(2, hash, filter);
      t2count[h2] += 4;
      t2hash[h2] ^= hash;
      t2count[h2] ^= 2U;
      if ((t2hash[h0] & t2hash[h1] & t2hash[h2]) == 0) {
        if   (((t2hash[h0] == 0) && (t2count[h0] == 8))
          ||  ((t2hash[h1] == 0) && (t2count[h1] == 8))
          ||  ((t2hash[h2] == 0) && (t2count[h2] == 8))) {
					duplicates += 1;
 					t2count[h0] -= 4;
 					t2hash[h0] ^= hash;
 					t2count[h1] -= 4;
 					t2count[h1] ^= 1U;
 					t2hash[h1] ^= hash;
 					t2count[h2] -= 4;
 					t2count[h2] ^= 2U;
 					t2hash[h2] ^= hash;
        }
      }
      error = (t2count[h0] < 4) ? 1 : error;
      error = (t2count[h1] < 4) ? 1 : error;
      error = (t2count[h2] < 4) ? 1 : error;
    }
    if(error) {
      memset(reverseOrder, 0, sizeof(uint64_t) * size);
      memset(t2count, 0, sizeof(uint8_t) * capacity);
      memset(t2hash, 0, sizeof(uint64_t) * capacity);
      filter->Seed = binary_fuse_rng_splitmix64(&rng_counter);
      continue;
    }

    // End of key addition
    uint32_t Qsize = 0;
    // Add sets with one key to the queue.
    for (uint32_t i = 0; i < capacity; i++) {
      alone[Qsize] = i;
      Qsize += ((t2count[i] >> 2U) == 1) ? 1U : 0U;
    }
    uint32_t stacksize = 0;
    while (Qsize > 0) {
      Qsize--;
      uint32_t index = alone[Qsize];
      if ((t2count[index] >> 2U) == 1) {
        uint64_t hash = t2hash[index];

        //h012[0] = binary_fuse8_hash(0, hash, filter);
        h012[1] = binary_fuse8_hash(1, hash, filter);
        h012[2] = binary_fuse8_hash(2, hash, filter);
        h012[3] = binary_fuse8_hash(0, hash, filter); // == h012[0];
        h012[4] = h012[1];
        uint8_t found = t2count[index] & 3U;
        reverseH[stacksize] = found;
        reverseOrder[stacksize] = hash;
        stacksize++;
        uint32_t other_index1 = h012[found + 1];
        alone[Qsize] = other_index1;
        Qsize += ((t2count[other_index1] >> 2U) == 2 ? 1U : 0U);

        t2count[other_index1] -= 4;
        t2count[other_index1] ^= binary_fuse_mod3(found + 1);
        t2hash[other_index1] ^= hash;

        uint32_t other_index2 = h012[found + 2];
        alone[Qsize] = other_index2;
        Qsize += ((t2count[other_index2] >> 2U) == 2 ? 1U : 0U);
        t2count[other_index2] -= 4;
        t2count[other_index2] ^= binary_fuse_mod3(found + 2);
        t2hash[other_index2] ^= hash;
      }
    }
    if (stacksize + duplicates == size) {
      // success
      size = stacksize;
      break;
    }
    if(duplicates > 0) {
      size = (uint32_t)binary_fuse_sort_and_remove_dup(keys, size);
    }
    memset(reverseOrder, 0, sizeof(uint64_t) * size);
    memset(t2count, 0, sizeof(uint8_t) * capacity);
    memset(t2hash, 0, sizeof(uint64_t) * capacity);
    filter->Seed = binary_fuse_rng_splitmix64(&rng_counter);
  }

  for (uint32_t i = size - 1; i < size; i--) {
    // the hash of the key we insert next
    uint64_t hash = reverseOrder[i];
    uint8_t xor2 = binary_fuse8_fingerprint(hash);
    uint8_t found = reverseH[i];
    h012[0] = binary_fuse8_hash(0, hash, filter);
    h012[1] = binary_fuse8_hash(1, hash, filter);
    h012[2] = binary_fuse8_hash(2, hash, filter);
    h012[3] = h012[0];
    h012[4] = h012[1];
    filter->Fingerprints[h012[found]] = (uint8_t)((uint32_t)xor2 ^
                                                  filter->Fingerprints[h012[found + 1]] ^
                                                  filter->Fingerprints[h012[found + 2]]);
  }
  free(alone);
  free(t2count);
  free(reverseH);
  free(t2hash);
  free(reverseOrder);
  free(startPos);
  return true;
}

//////////////////
// fuse16
//////////////////

typedef struct binary_fuse16_s {
  uint64_t Seed;
  uint32_t Size;
  uint32_t SegmentLength;
  uint32_t SegmentLengthMask;
  uint32_t SegmentCount;
  uint32_t SegmentCountLength;
  uint32_t ArrayLength;
  uint16_t *Fingerprints;
} binary_fuse16_t;

static inline uint16_t binary_fuse16_fingerprint(uint64_t hash) {
  return (uint16_t)(hash ^ (hash >> 32U));
}

static inline binary_hashes_t binary_fuse16_hash_batch(uint64_t hash,
                                        const binary_fuse16_t *filter) {
  uint64_t hi = binary_fuse_mulhi(hash, filter->SegmentCountLength);
  binary_hashes_t ans;
  ans.h0 = (uint32_t)hi;
  ans.h1 = ans.h0 + filter->SegmentLength;
  ans.h2 = ans.h1 + filter->SegmentLength;
  ans.h1 ^= (uint32_t)(hash >> 18U) & filter->SegmentLengthMask;
  ans.h2 ^= (uint32_t)(hash)&filter->SegmentLengthMask;
  return ans;
}
static inline uint32_t binary_fuse16_hash(uint64_t index, uint64_t hash,
                                        const binary_fuse16_t *filter) {
    uint64_t h = binary_fuse_mulhi(hash, filter->SegmentCountLength);
    h += index * filter->SegmentLength;
    // keep the lower 36 bits
    uint64_t hh = hash & ((1ULL << 36U) - 1);
    // index 0: right shift by 36; index 1: right shift by 18; index 2: no shift
    h ^= (size_t)((hh >> (36 - 18 * index)) & filter->SegmentLengthMask);
    return (uint32_t)h;
}

// Report if the key is in the set, with false positive rate.
static inline bool binary_fuse16_contain(uint64_t key,
                                        const binary_fuse16_t *filter) {
  uint64_t hash = binary_fuse_mix_split(key, filter->Seed);
  uint16_t f = binary_fuse16_fingerprint(hash);
  binary_hashes_t hashes = binary_fuse16_hash_batch(hash, filter);
  f ^= (uint32_t)filter->Fingerprints[hashes.h0] ^
       filter->Fingerprints[hashes.h1] ^
       filter->Fingerprints[hashes.h2];
  return f == 0;
}


// allocate enough capacity for a set containing up to 'size' elements
// caller is responsible to call binary_fuse16_free(filter)
// size should be at least 2.
static inline bool binary_fuse16_allocate(uint32_t size,
                                         binary_fuse16_t *filter) {
  uint32_t arity = 3;
  filter->Size = size;
  filter->SegmentLength = size == 0 ? 4 : binary_fuse_calculate_segment_length(arity, size);
  if (filter->SegmentLength > 262144) {
    filter->SegmentLength = 262144;
  }
  filter->SegmentLengthMask = filter->SegmentLength - 1;
  double sizeFactor = size <= 1 ? 0 : binary_fuse_calculate_size_factor(arity, size);
  uint32_t capacity = size <= 1 ? 0 : (uint32_t)(round((double)size * sizeFactor));
  uint32_t initSegmentCount =
      (capacity + filter->SegmentLength - 1) / filter->SegmentLength -
      (arity - 1);
  filter->ArrayLength = (initSegmentCount + arity - 1) * filter->SegmentLength;
  filter->SegmentCount =
      (filter->ArrayLength + filter->SegmentLength - 1) / filter->SegmentLength;
  if (filter->SegmentCount <= arity - 1) {
    filter->SegmentCount = 1;
  } else {
    filter->SegmentCount = filter->SegmentCount - (arity - 1);
  }
  filter->ArrayLength =
      (filter->SegmentCount + arity - 1) * filter->SegmentLength;
  filter->SegmentCountLength = filter->SegmentCount * filter->SegmentLength;
  filter->Fingerprints =
      (uint16_t *)calloc(filter->ArrayLength, sizeof(uint16_t));
  return filter->Fingerprints != NULL;
}

// report memory usage
static inline size_t binary_fuse16_size_in_bytes(const binary_fuse16_t *filter) {
  return filter->ArrayLength * sizeof(uint16_t) + sizeof(binary_fuse16_t);
}

// release memory
static inline void binary_fuse16_free(binary_fuse16_t *filter) {
  free(filter->Fingerprints);
  filter->Fingerprints = NULL;
  filter->Seed = 0;
  filter->Size = 0;
  filter->SegmentLength = 0;
  filter->SegmentLengthMask = 0;
  filter->SegmentCount = 0;
  filter->SegmentCountLength = 0;
  filter->ArrayLength = 0;
}


// Construct the filter, returns true on success, false on failure.
// The algorithm fails when there is insufficient memory.
// The caller is responsable for calling binary_fuse8_allocate(size,filter)
// before. For best performance, the caller should ensure that there are not too
// many duplicated keys.
static inline bool binary_fuse16_populate(uint64_t *keys, uint32_t size,
                           binary_fuse16_t *filter) {
  if (size != filter->Size) {
    return false;
  }

  uint64_t rng_counter = 0x726b2b9d438b9d4d;
  filter->Seed = binary_fuse_rng_splitmix64(&rng_counter);
  uint64_t *reverseOrder = (uint64_t *)calloc((size + 1), sizeof(uint64_t));
  uint32_t capacity = filter->ArrayLength;
  uint32_t *alone = (uint32_t *)malloc(capacity * sizeof(uint32_t));
  uint8_t *t2count = (uint8_t *)calloc(capacity, sizeof(uint8_t));
  uint8_t *reverseH = (uint8_t *)malloc(size * sizeof(uint8_t));
  uint64_t *t2hash = (uint64_t *)calloc(capacity, sizeof(uint64_t));

  uint32_t blockBits = 1;
  while (((uint32_t)1 << blockBits) < filter->SegmentCount) {
    blockBits += 1;
  }
  uint32_t block = ((uint32_t)1 << blockBits);
  uint32_t *startPos = (uint32_t *)malloc((1U << blockBits) * sizeof(uint32_t));
  uint32_t h012[5];

  if ((alone == NULL) || (t2count == NULL) || (reverseH == NULL) ||
      (t2hash == NULL) || (reverseOrder == NULL) || (startPos == NULL)) {
    free(alone);
    free(t2count);
    free(reverseH);
    free(t2hash);
    free(reverseOrder);
    free(startPos);
    return false;
  }
  reverseOrder[size] = 1;
  for (int loop = 0; true; ++loop) {
    if (loop + 1 > XOR_MAX_ITERATIONS) {
      // The probability of this happening is lower than the
      // the cosmic-ray probability (i.e., a cosmic ray corrupts your system).
      free(alone);
      free(t2count);
      free(reverseH);
      free(t2hash);
      free(reverseOrder);
      free(startPos);
      return false;
    }

    for (uint32_t i = 0; i < block; i++) {
      // important : i * size would overflow as a 32-bit number in some
      // cases.
      startPos[i] = (uint32_t)(((uint64_t)i * size) >> blockBits);
    }

    uint64_t maskblock = block - 1;
    for (uint32_t i = 0; i < size; i++) {
      uint64_t hash = binary_fuse_murmur64(keys[i] + filter->Seed);
      uint64_t segment_index = hash >> (64 - blockBits);
      while (reverseOrder[startPos[segment_index]] != 0) {
        segment_index++;
        segment_index &= maskblock;
      }
      reverseOrder[startPos[segment_index]] = hash;
      startPos[segment_index]++;
    }
    int error = 0;
    uint32_t duplicates = 0;
    for (uint32_t i = 0; i < size; i++) {
      uint64_t hash = reverseOrder[i];
      uint32_t h0 = binary_fuse16_hash(0, hash, filter);
      t2count[h0] += 4;
      t2hash[h0] ^= hash;
      uint32_t h1= binary_fuse16_hash(1, hash, filter);
      t2count[h1] += 4;
      t2count[h1] ^= 1U;
      t2hash[h1] ^= hash;
      uint32_t h2 = binary_fuse16_hash(2, hash, filter);
      t2count[h2] += 4;
      t2hash[h2] ^= hash;
      t2count[h2] ^= 2U;
      if ((t2hash[h0] & t2hash[h1] & t2hash[h2]) == 0) {
        if   (((t2hash[h0] == 0) && (t2count[h0] == 8))
          ||  ((t2hash[h1] == 0) && (t2count[h1] == 8))
          ||  ((t2hash[h2] == 0) && (t2count[h2] == 8))) {
					duplicates += 1;
 					t2count[h0] -= 4;
 					t2hash[h0] ^= hash;
 					t2count[h1] -= 4;
 					t2count[h1] ^= 1U;
 					t2hash[h1] ^= hash;
 					t2count[h2] -= 4;
 					t2count[h2] ^= 2U;
 					t2hash[h2] ^= hash;
        }
      }
      error = (t2count[h0] < 4) ? 1 : error;
      error = (t2count[h1] < 4) ? 1 : error;
      error = (t2count[h2] < 4) ? 1 : error;
    }
    if(error) {
      memset(reverseOrder, 0, sizeof(uint64_t) * size);
      memset(t2count, 0, sizeof(uint8_t) * capacity);
      memset(t2hash, 0, sizeof(uint64_t) * capacity);
      filter->Seed = binary_fuse_rng_splitmix64(&rng_counter);
      continue;
    }

    // End of key addition
    uint32_t Qsize = 0;
    // Add sets with one key to the queue.
    for (uint32_t i = 0; i < capacity; i++) {
      alone[Qsize] = i;
      Qsize += ((t2count[i] >> 2U) == 1) ? 1U : 0U;
    }
    uint32_t stacksize = 0;
    while (Qsize > 0) {
      Qsize--;
      uint32_t index = alone[Qsize];
      if ((t2count[index] >> 2U) == 1) {
        uint64_t hash = t2hash[index];

        //h012[0] = binary_fuse16_hash(0, hash, filter);
        h012[1] = binary_fuse16_hash(1, hash, filter);
        h012[2] = binary_fuse16_hash(2, hash, filter);
        h012[3] = binary_fuse16_hash(0, hash, filter); // == h012[0];
        h012[4] = h012[1];
        uint8_t found = t2count[index] & 3U;
        reverseH[stacksize] = found;
        reverseOrder[stacksize] = hash;
        stacksize++;
        uint32_t other_index1 = h012[found + 1];
        alone[Qsize] = other_index1;
        Qsize += ((t2count[other_index1] >> 2U) == 2 ? 1U : 0U);

        t2count[other_index1] -= 4;
        t2count[other_index1] ^= binary_fuse_mod3(found + 1);
        t2hash[other_index1] ^= hash;

        uint32_t other_index2 = h012[found + 2];
        alone[Qsize] = other_index2;
        Qsize += ((t2count[other_index2] >> 2U) == 2 ? 1U : 0U);
        t2count[other_index2] -= 4;
        t2count[other_index2] ^= binary_fuse_mod3(found + 2);
        t2hash[other_index2] ^= hash;
      }
    }
    if (stacksize + duplicates == size) {
      // success
      size = stacksize;
      break;
    }
    if(duplicates > 0) {
      size = (uint32_t)binary_fuse_sort_and_remove_dup(keys, size);
    }
    memset(reverseOrder, 0, sizeof(uint64_t) * size);
    memset(t2count, 0, sizeof(uint8_t) * capacity);
    memset(t2hash, 0, sizeof(uint64_t) * capacity);
    filter->Seed = binary_fuse_rng_splitmix64(&rng_counter);
  }

  for (uint32_t i = size - 1; i < size; i--) {
    // the hash of the key we insert next
    uint64_t hash = reverseOrder[i];
    uint16_t xor2 = binary_fuse16_fingerprint(hash);
    uint8_t found = reverseH[i];
    h012[0] = binary_fuse16_hash(0, hash, filter);
    h012[1] = binary_fuse16_hash(1, hash, filter);
    h012[2] = binary_fuse16_hash(2, hash, filter);
    h012[3] = h012[0];
    h012[4] = h012[1];
    filter->Fingerprints[h012[found]] = (uint16_t)(
        (uint32_t)xor2 ^
        (uint32_t)filter->Fingerprints[h012[found + 1]] ^
        (uint32_t)filter->Fingerprints[h012[found + 2]]);
  }
  free(alone);
  free(t2count);
  free(reverseH);
  free(t2hash);
  free(reverseOrder);
  free(startPos);
  return true;
}

static inline size_t binary_fuse16_serialization_bytes(binary_fuse16_t *filter) {
  return sizeof(filter->Seed) + sizeof(filter->Size) + sizeof(filter->SegmentLength) +
        sizeof(filter->SegmentLengthMask) + sizeof(filter->SegmentCount) +
        sizeof(filter->SegmentCountLength) + sizeof(filter->ArrayLength) +
        sizeof(uint16_t) * filter->ArrayLength;
}

static inline size_t binary_fuse8_serialization_bytes(const binary_fuse8_t *filter) {
  return sizeof(filter->Seed) + sizeof(filter->Size) + sizeof(filter->SegmentLength) +
   sizeof(filter->SegmentCount) +
        sizeof(filter->SegmentCountLength) + sizeof(filter->ArrayLength) +
        sizeof(uint8_t) * filter->ArrayLength;
}

// serialize a filter to a buffer, the buffer should have a capacity of at least
// binary_fuse16_serialization_bytes(filter) bytes.
// Native endianess only.
static inline void binary_fuse16_serialize(const binary_fuse16_t *filter, char *buffer) {
  memcpy(buffer, &filter->Seed, sizeof(filter->Seed));
  buffer += sizeof(filter->Seed);
  memcpy(buffer, &filter->Size, sizeof(filter->Size));
  buffer += sizeof(filter->Size);
  memcpy(buffer, &filter->SegmentLength, sizeof(filter->SegmentLength));
  buffer += sizeof(filter->SegmentLength);
  memcpy(buffer, &filter->SegmentCount, sizeof(filter->SegmentCount));
  buffer += sizeof(filter->SegmentCount);
  memcpy(buffer, &filter->SegmentCountLength, sizeof(filter->SegmentCountLength));
  buffer += sizeof(filter->SegmentCountLength);
  memcpy(buffer, &filter->ArrayLength, sizeof(filter->ArrayLength));
  buffer += sizeof(filter->ArrayLength);
  memcpy(buffer, filter->Fingerprints, filter->ArrayLength * sizeof(uint16_t));
}

// serialize a filter to a buffer, the buffer should have a capacity of at least
// binary_fuse8_serialization_bytes(filter) bytes.
// Native endianess only.
static inline void binary_fuse8_serialize(const binary_fuse8_t *filter, char *buffer) {
  memcpy(buffer, &filter->Seed, sizeof(filter->Seed));
  buffer += sizeof(filter->Seed);
  memcpy(buffer, &filter->Size, sizeof(filter->Size));
  buffer += sizeof(filter->Size);
  memcpy(buffer, &filter->SegmentLength, sizeof(filter->SegmentLength));
  buffer += sizeof(filter->SegmentLength);
  memcpy(buffer, &filter->SegmentCount, sizeof(filter->SegmentCount));
  buffer += sizeof(filter->SegmentCount);
  memcpy(buffer, &filter->SegmentCountLength, sizeof(filter->SegmentCountLength));
  buffer += sizeof(filter->SegmentCountLength);
  memcpy(buffer, &filter->ArrayLength, sizeof(filter->ArrayLength));
  buffer += sizeof(filter->ArrayLength);
  memcpy(buffer, filter->Fingerprints, filter->ArrayLength * sizeof(uint8_t));
}

// deserialize the main struct fields of a filter from a buffer, returns the buffer position
// immediately after those fields. If you used binary_fuse16_seriliaze the return value will point at
// the start of the `Fingerprints` array. Use this option if you want to allocate your own memory or
// perhaps have the memory `mmap`ed to a file. Nothing is allocated. Do not call binary_fuse16_free
// on the returned pointer. Native endianess only.
static inline const char* binary_fuse16_deserialize_header(binary_fuse16_t* filter, const char* buffer) {
  memcpy(&filter->Seed, buffer, sizeof(filter->Seed));
  buffer += sizeof(filter->Seed);
  memcpy(&filter->Size, buffer, sizeof(filter->Size));
  buffer += sizeof(filter->Size);
  memcpy(&filter->SegmentLength, buffer, sizeof(filter->SegmentLength));
  buffer += sizeof(filter->SegmentLength);
  filter->SegmentLengthMask = filter->SegmentLength - 1;
  memcpy(&filter->SegmentCount, buffer, sizeof(filter->SegmentCount));
  buffer += sizeof(filter->SegmentCount);
  memcpy(&filter->SegmentCountLength, buffer, sizeof(filter->SegmentCountLength));
  buffer += sizeof(filter->SegmentCountLength);
  memcpy(&filter->ArrayLength, buffer, sizeof(filter->ArrayLength));
  buffer += sizeof(filter->ArrayLength);
  return buffer;
}

// deserialize a filter from a buffer, returns true on success, false on failure.
// The output will be reallocated, so the caller should call binary_fuse16_free(filter) before
// if the filter was already allocated. The caller needs to call binary_fuse16_free(filter) after.
// The number of bytes read is binary_fuse16_serialization_bytes(output).
// Native endianess only.
static inline bool binary_fuse16_deserialize(binary_fuse16_t * filter, const char *buffer) {
  const char* fingerprints = binary_fuse16_deserialize_header(filter, buffer);
  filter->Fingerprints = (uint16_t*)malloc(filter->ArrayLength * sizeof(uint16_t));
  if(filter->Fingerprints == NULL) {
    return false;
  }
  memcpy(filter->Fingerprints, fingerprints, filter->ArrayLength * sizeof(uint16_t));
  return true;
}

// deserialize the main struct fields of a filter from a buffer, returns the buffer position
// immediately after those fields. If you used binary_fuse8_seriliaze the return value will point at
// the start of the `Fingerprints` array. Use this option if you want to allocate your own memory or
// perhaps have the memory `mmap`ed to a file. Nothing is allocated. Do not call binary_fuse8_free
// on the returned pointer. Native endianess only.
static inline const char* binary_fuse8_deserialize_header(binary_fuse8_t* filter, const char* buffer) {
  memcpy(&filter->Seed, buffer, sizeof(filter->Seed));
  buffer += sizeof(filter->Seed);
  memcpy(&filter->Size, buffer, sizeof(filter->Size));
  buffer += sizeof(filter->Size);
  memcpy(&filter->SegmentLength, buffer, sizeof(filter->SegmentLength));
  buffer += sizeof(filter->SegmentLength);
  filter->SegmentLengthMask = filter->SegmentLength - 1;
  memcpy(&filter->SegmentCount, buffer, sizeof(filter->SegmentCount));
  buffer += sizeof(filter->SegmentCount);
  memcpy(&filter->SegmentCountLength, buffer, sizeof(filter->SegmentCountLength));
  buffer += sizeof(filter->SegmentCountLength);
  memcpy(&filter->ArrayLength, buffer, sizeof(filter->ArrayLength));
  buffer += sizeof(filter->ArrayLength);
  return buffer;
}

// deserialize a filter from a buffer, returns true on success, false on failure.
// The output will be reallocated, so the caller should call binary_fuse8_free(filter) before
// if the filter was already allocated. The caller needs to call binary_fuse8_free(filter) after.
// The number of bytes read is binary_fuse8_serialization_bytes(output).
// Native endianess only.
static inline bool binary_fuse8_deserialize(binary_fuse8_t * filter, const char *buffer) {
  const char* fingerprints = binary_fuse8_deserialize_header(filter, buffer);
  filter->Fingerprints = (uint8_t*)malloc(filter->ArrayLength * sizeof(uint8_t));
  if(filter->Fingerprints == NULL) {
    return false;
  }
  memcpy(filter->Fingerprints, fingerprints, filter->ArrayLength * sizeof(uint8_t));
  return true;
}

// minimal bitfield implementation
#define XOR_bitf_w (sizeof(uint8_t) * 8)
#define XOR_bitf_sz(bits) (((bits) + XOR_bitf_w - 1) / XOR_bitf_w)
#define XOR_bitf_word(bit) (bit / XOR_bitf_w)
#define XOR_bitf_bit(bit) ((1U << (bit % XOR_bitf_w)) % 256)

#define XOR_ser(buf, lim, src) do {			\
	if ((buf) + sizeof src > (lim))		\
	  return (0);				\
	memcpy(buf, &src, sizeof src);		\
	buf += sizeof src;			\
} while (0)

#define XOR_deser(dst, buf, lim) do {		\
	if ((buf) + sizeof dst > (lim))		\
	  return (false);			\
	memcpy(&dst, buf, sizeof dst);		\
	buf += sizeof dst;			\
} while (0)

// return required space for binary_fuse{8,16}_pack()
#define XOR_bytesf(fuse) \
static inline size_t binary_ ## fuse ## _pack_bytes(const binary_ ## fuse ## _t *filter) \
{ \
  size_t sz = 0; \
  sz += sizeof filter->Seed; \
  sz += sizeof filter->Size; \
  sz += XOR_bitf_sz(filter->ArrayLength); \
  for (size_t i = 0; i < filter->ArrayLength; i++) { \
    if (filter->Fingerprints[i] == 0) \
      continue; \
    sz += sizeof filter->Fingerprints[i]; \
  } \
  return (sz); \
}

// serialize as packed format, return size used or 0 for insufficient space
#define XOR_packf(fuse) \
static inline size_t binary_ ## fuse ## _pack(const binary_ ## fuse ## _t *filter, char *buffer, size_t space) { \
  uint8_t *s = (uint8_t *)(void *)buffer; \
  uint8_t *buf = s, *e = buf + space; \
 \
  XOR_ser(buf, e, filter->Seed); \
  XOR_ser(buf, e, filter->Size); \
  size_t bsz = XOR_bitf_sz(filter->ArrayLength); \
  if (buf + bsz > e) \
    return (0); \
  uint8_t *bitf = buf; \
  memset(bitf, 0, bsz); \
  buf += bsz; \
 \
  for (size_t i = 0; i < filter->ArrayLength; i++) { \
    if (filter->Fingerprints[i] == 0) \
      continue; \
    bitf[XOR_bitf_word(i)] |= XOR_bitf_bit(i); \
    XOR_ser(buf, e, filter->Fingerprints[i]); \
  } \
  return ((size_t)(buf - s)); \
}

#define XOR_unpackf(fuse) \
static inline bool binary_ ## fuse ## _unpack(binary_ ## fuse ## _t *filter, const char *buffer, size_t len) \
{ \
  const uint8_t *s = (const uint8_t *)(const void *)buffer; \
  const uint8_t *buf = s, *e = buf + len; \
  bool r; \
 \
  uint64_t Seed; \
  uint32_t Size; \
 \
  memset(filter, 0, sizeof *filter); \
  XOR_deser(Seed, buf, e); \
  XOR_deser(Size, buf, e); \
  r = binary_ ## fuse ## _allocate(Size, filter); \
  if (! r) \
    return (r); \
  filter->Seed = Seed; \
  const uint8_t *bitf = buf; \
  buf += XOR_bitf_sz(filter->ArrayLength); \
  for (size_t i = 0; i < filter->ArrayLength; i++) { \
    if ((bitf[XOR_bitf_word(i)] & XOR_bitf_bit(i)) == 0) \
      continue; \
    XOR_deser(filter->Fingerprints[i], buf, e); \
  } \
  return (true); \
}

#define XOR_packers(fuse) \
XOR_bytesf(fuse) \
XOR_packf(fuse) \
XOR_unpackf(fuse) \

XOR_packers(fuse8)
XOR_packers(fuse16)

#undef XOR_packers
#undef XOR_bytesf
#undef XOR_packf
#undef XOR_unpackf

#undef XOR_bitf_w
#undef XOR_bitf_sz
#undef XOR_bitf_word
#undef XOR_bitf_bit
#undef XOR_ser
#undef XOR_deser

#endif
