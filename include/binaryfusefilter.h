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
#define XOR_MAX_ITERATIONS                                                     \
  100 // probabillity of success should always be > 0.5 so 100 iterations is
      // highly unlikely
#endif

/**
 * We start with a few utilities.
 ***/
static inline uint64_t binary_fuse_murmur64(uint64_t h) {
  h ^= h >> 33;
  h *= UINT64_C(0xff51afd7ed558ccd);
  h ^= h >> 33;
  h *= UINT64_C(0xc4ceb9fe1a85ec53);
  h ^= h >> 33;
  return h;
}

static inline uint64_t binary_fuse_mix_split(uint64_t key, uint64_t seed) {
  return binary_fuse_murmur64(key + seed);
}

static inline uint64_t binary_fuse_rotl64(uint64_t n, unsigned int c) {
  return (n << (c & 63)) | (n >> ((-c) & 63));
}

static inline uint32_t binary_fuse_reduce(uint32_t hash, uint32_t n) {
  // http://lemire.me/blog/2016/06/27/a-fast-alternative-to-the-modulo-reduction/
  return (uint32_t)(((uint64_t)hash * n) >> 32);
}

static inline uint64_t binary_fuse8_fingerprint(uint64_t hash) {
  return hash ^ (hash >> 32);
}

/**
 * We need a decent random number generator.
 **/

// returns random number, modifies the seed
static inline uint64_t binary_fuse_rng_splitmix64(uint64_t *seed) {
  uint64_t z = (*seed += UINT64_C(0x9E3779B97F4A7C15));
  z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
  z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
  return z ^ (z >> 31);
}

typedef struct binary_fuse8_s {
  uint64_t Seed;
  uint32_t SegmentLength;
  uint32_t SegmentLengthMask;
  uint32_t SegmentCount;
  uint32_t SegmentCountLength;
  uint32_t ArrayLength;
  uint8_t *Fingerprints;
} binary_fuse8_t;

#ifdef _MSC_VER
// Windows programmers who target 32-bit platform may need help:
uint64_t binary_fuse_mulhi(uint64_t a, uint64_t b) { return __umulh(a, b); }
#else
uint64_t binary_fuse_mulhi(uint64_t a, uint64_t b) {
  return ((__uint128_t)a * b) >> 64;
}
#endif

typedef struct binary_hashes_s {
  uint32_t h0;
  uint32_t h1;
  uint32_t h2;
} binary_hashes_t;

static binary_hashes_t binary_fuse_hash(uint64_t hash,
                                        const binary_fuse8_t *filter) {
  uint64_t hi = binary_fuse_mulhi(hash, filter->SegmentCountLength);
  binary_hashes_t ans;
  ans.h0 = (uint32_t)hi;
  ans.h1 = ans.h0 + filter->SegmentLength;
  ans.h2 = ans.h1 + filter->SegmentLength;
  ans.h1 ^= (uint32_t)(hash >> 18) & filter->SegmentLengthMask;
  ans.h2 ^= (uint32_t)(hash)&filter->SegmentLengthMask;
  return ans;
}

// Report if the key is in the set, with false positive rate.
static inline bool binary_fuse8_contain(uint64_t key,
                                        const binary_fuse8_t *filter) {
  uint64_t hash = binary_fuse_mix_split(key, filter->Seed);
  uint8_t f = binary_fuse8_fingerprint(hash);
  binary_hashes_t hashes = binary_fuse_hash(hash, filter);
  f ^= filter->Fingerprints[hashes.h0] ^ filter->Fingerprints[hashes.h1] ^
       filter->Fingerprints[hashes.h2];
  return f == 0;
}

static inline uint32_t binary_fuse8_calculate_segment_length(uint32_t arity,
                                                             uint32_t size) {
  if (arity == 3) {
    return ((uint32_t)2) << (int)(round(0.831 * log((double)(size)) + 0.75 +
                                        0.5));
  } else if (arity == 4) {
    return ((uint32_t)1) << (int)(round(0.936 * log((double)(size)) - 1 + 0.5));
  } else {
    return 65536;
  }
}

double binary_fuse8_max(double a, double b) {
  if (a < b) {
    return b;
  }
  return a;
}

static inline double binary_fuse8_calculate_size_factor(uint32_t arity,
                                                        uint32_t size) {
  if (arity == 3) {
    return binary_fuse8_max(1.125, 0.4 + 9.3 / log((double)size));
  } else if (arity == 4) {
    return binary_fuse8_max(1.075, 0.77 + 4.06 / log((double)size));
  } else {
    return 2.0;
  }
}

// allocate enough capacity for a set containing up to 'size' elements
// caller is responsible to call binary_fuse8_free(filter)
static inline bool binary_fuse8_allocate(uint32_t size,
                                         binary_fuse8_t *filter) {
  uint32_t arity = 3;
  filter->SegmentLength = binary_fuse8_calculate_segment_length(arity, size);
  if (filter->SegmentLength > 262144) {
    filter->SegmentLength = 262144;
  }
  filter->SegmentLengthMask = filter->SegmentLength - 1;
  double sizeFactor = binary_fuse8_calculate_size_factor(arity, size);
  uint32_t capacity = (uint32_t)(round((double)size * sizeFactor));
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
  filter->Fingerprints = malloc(filter->ArrayLength);
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
  filter->SegmentLength = 0;
  filter->SegmentLengthMask = 0;
  filter->SegmentCount = 0;
  filter->SegmentCountLength = 0;
  filter->ArrayLength = 0;
}

static inline uint8_t binary_fuse8_mod3(uint8_t x) {
  if (x > 2) {
    x -= 3;
  }
  return x;
}

// construct the filter, returns true on success, false on failure.
// most likely, a failure is due to too high a memory usage
// size is the number of keys
// The caller is responsable for calling binary_fuse8_allocate(size,filter)
// before. The caller is responsible to ensure that there are no duplicated
// keys. The inner loop will run up to XOR_MAX_ITERATIONS times (default on
// 100), it should never fail, except if there are duplicated keys. If it fails,
// a return value of false is provided.
//
bool binary_fuse8_populate(const uint64_t *keys, uint32_t size,
                           binary_fuse8_t *filter) {
  uint64_t rng_counter = 1;
  filter->Seed = binary_fuse_rng_splitmix64(&rng_counter);
  uint32_t capacity = filter->ArrayLength;
  uint32_t *alone = calloc(capacity, sizeof(uint32_t));
  uint8_t *t2count = calloc(capacity, sizeof(uint8_t));
  uint8_t *reverseH = calloc(size, sizeof(uint8_t));
  uint64_t *t2hash = calloc(capacity, sizeof(uint64_t));
  uint64_t *reverseOrder = calloc((size + 1), sizeof(uint64_t));
  // the array h0, h1, h2, h0, h1, h2
  uint32_t blockBits = 1;
  while ((1 << blockBits) < filter->SegmentCount) {
    blockBits += 1;
  }
  uint32_t *startPos = calloc((1 << blockBits), sizeof(uint32_t));
  uint32_t h012[6];

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
      fprintf(stderr, "Too many iterations. Are all your keys unique?");
      free(alone);
      free(t2count);
      free(reverseH);
      free(t2hash);
      free(reverseOrder);
      free(startPos);
      return false;
    }
    for (uint32_t i = 0; i < (1 << blockBits); i++) {
      startPos[i] = (i * size) >> blockBits;
    }
    for (uint32_t i = 0; i < size; i++) {
      uint64_t hash = binary_fuse_mix_split(keys[i], filter->Seed);
      uint32_t segment_index = hash >> (64 - blockBits);
      while (reverseOrder[startPos[segment_index]] != 0) {
        segment_index++;
        segment_index &= (1 << blockBits) - 1;
      }
      reverseOrder[startPos[segment_index]] = hash;
      startPos[segment_index] += 1;
    }
    for (uint32_t i = 0; i < size; i++) {
      uint64_t hash = reverseOrder[i];
      binary_hashes_t hashes = binary_fuse_hash(hash, filter);
      t2count[hashes.h0] += 4;
      // t2count[hashes.h0] ^= 0 // noop
      t2hash[hashes.h0] ^= hash;
      t2count[hashes.h1] += 4;
      t2count[hashes.h1] ^= 1;
      t2hash[hashes.h1] ^= hash;
      t2count[hashes.h2] += 4;
      t2count[hashes.h2] ^= 2;
      t2hash[hashes.h2] ^= hash;
      if ((t2count[hashes.h0] < 4) || (t2count[hashes.h1] < 4) ||
          (t2count[hashes.h2] < 4)) {
        break;
      }
    }

    // End of key addition

    uint32_t Qsize = 0;
    // Add sets with one key to the queue.
    for (uint32_t i = 0; i < capacity; i++) {
      alone[Qsize] = i;
      if ((t2count[i] >> 2) == 1) {
        Qsize++;
      }
    }
    uint32_t stacksize = 0;
    while (Qsize > 0) {
      Qsize--;
      uint32_t index = alone[Qsize];
      if ((t2count[index] >> 2) == 1) {
        uint64_t hash = t2hash[index];
        uint8_t found = t2count[index] & 3;
        reverseH[stacksize] = found;
        reverseOrder[stacksize] = hash;
        stacksize++;
        binary_hashes_t hashes = binary_fuse_hash(hash, filter);

        h012[1] = hashes.h1;
        h012[2] = hashes.h2;
        h012[3] = hashes.h0;
        h012[4] = h012[1];

        uint32_t other_index1 = h012[found + 1];
        alone[Qsize] = other_index1;
        if ((t2count[other_index1] >> 2) == 2) {
          Qsize++;
        }
        t2count[other_index1] -= 4;
        t2count[other_index1] ^= binary_fuse8_mod3(
            found + 1); // could use this instead: tabmod3[found+1]
        t2hash[other_index1] ^= hash;

        uint32_t other_index2 = h012[found + 2];
        alone[Qsize] = other_index2;
        if ((t2count[other_index2] >> 2) == 2) {
          Qsize++;
        }
        t2count[other_index2] -= 4;
        t2count[other_index2] ^= binary_fuse8_mod3(
            found + 2); // could use this instead: tabmod3[found+2]
        t2hash[other_index2] ^= hash;
      }
    }
    if (stacksize == size) {
      // success
      break;
    }

    for (uint32_t i = 0; i < size; i++) {
      reverseOrder[i] = 0;
    }
    for (uint32_t i = 0; i < capacity; i++) {
      t2count[i] = 0;
    }
    for (uint32_t i = 0; i < capacity; i++) {
      t2hash[i] = 0;
    }

    filter->Seed = binary_fuse_rng_splitmix64(&rng_counter);
  }
  for (uint32_t i = size - 1; i < size; i--) {
    // the hash of the key we insert next
    uint64_t hash = reverseOrder[i];
    uint8_t xor2 = binary_fuse8_fingerprint(hash);
    binary_hashes_t hashes = binary_fuse_hash(hash, filter);

    uint8_t found = reverseH[i];
    h012[0] = hashes.h0;
    h012[1] = hashes.h1;
    h012[2] = hashes.h2;
    h012[3] = h012[0];
    h012[4] = h012[1];
    filter->Fingerprints[h012[found]] = xor2 ^
                                        filter->Fingerprints[h012[found + 1]] ^
                                        filter->Fingerprints[h012[found + 2]];
  }
  free(alone);
  free(t2count);
  free(reverseH);
  free(t2hash);
  free(reverseOrder);
  free(startPos);
  return true;
}

#endif