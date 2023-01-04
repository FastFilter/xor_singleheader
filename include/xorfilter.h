#ifndef XORFILTER_H
#define XORFILTER_H
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
  return f == (filter->fingerprints[h0] ^ filter->fingerprints[h1] ^
       filter->fingerprints[h2]);
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
  return f == (filter->fingerprints[h0] ^ filter->fingerprints[h1] ^
       filter->fingerprints[h2]);
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
// caller is responsible to call xor16_free(filter)
static inline bool xor16_allocate(uint32_t size, xor16_t *filter) {
  size_t capacity = 32 + 1.23 * size;
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
  uint32_t count;
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
  answer.h1 = xor_reduce(r1, filter->blockLength);
  answer.h2 = xor_reduce(r2, filter->blockLength);
  return answer;
}

struct xor_h0h1h2_s {
  uint32_t h0;
  uint32_t h1;
  uint32_t h2;
};

typedef struct xor_h0h1h2_s xor_h0h1h2_t;

static inline uint32_t xor8_get_h0(uint64_t hash, const xor8_t *filter) {
  uint32_t r0 = (uint32_t)hash;
  return xor_reduce(r0, filter->blockLength);
}
static inline uint32_t xor8_get_h1(uint64_t hash, const xor8_t *filter) {
  uint32_t r1 = (uint32_t)xor_rotl64(hash, 21);
  return xor_reduce(r1, filter->blockLength);
}
static inline uint32_t xor8_get_h2(uint64_t hash, const xor8_t *filter) {
  uint32_t r2 = (uint32_t)xor_rotl64(hash, 42);
  return xor_reduce(r2, filter->blockLength);
}
static inline uint32_t xor16_get_h0(uint64_t hash, const xor16_t *filter) {
  uint32_t r0 = (uint32_t)hash;
  return xor_reduce(r0, filter->blockLength);
}
static inline uint32_t xor16_get_h1(uint64_t hash, const xor16_t *filter) {
  uint32_t r1 = (uint32_t)xor_rotl64(hash, 21);
  return xor_reduce(r1, filter->blockLength);
}
static inline uint32_t xor16_get_h2(uint64_t hash, const xor16_t *filter) {
  uint32_t r2 = (uint32_t)xor_rotl64(hash, 42);
  return xor_reduce(r2, filter->blockLength);
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
  answer.h1 = xor_reduce(r1, filter->blockLength);
  answer.h2 = xor_reduce(r2, filter->blockLength);
  return answer;
}

struct xor_keyindex_s {
  uint64_t hash;
  uint32_t index;
};

typedef struct xor_keyindex_s xor_keyindex_t;

struct xor_setbuffer_s {
  xor_keyindex_t *buffer;
  uint32_t *counts;
  int insignificantbits;
  uint32_t slotsize; // should be 1<< insignificantbits
  uint32_t slotcount;
  size_t originalsize;
};

typedef struct xor_setbuffer_s xor_setbuffer_t;

static inline bool xor_init_buffer(xor_setbuffer_t *buffer, size_t size) {
  buffer->originalsize = size;
  buffer->insignificantbits = 18;
  buffer->slotsize = UINT32_C(1) << buffer->insignificantbits;
  buffer->slotcount = (size + buffer->slotsize - 1) / buffer->slotsize;
  buffer->buffer = (xor_keyindex_t *)malloc(
      buffer->slotcount * buffer->slotsize * sizeof(xor_keyindex_t));
  buffer->counts = (uint32_t *)malloc(buffer->slotcount * sizeof(uint32_t));
  if ((buffer->counts == NULL) || (buffer->buffer == NULL)) {
    free(buffer->counts);
    free(buffer->buffer);
    return false;
  }
  memset(buffer->counts, 0, buffer->slotcount * sizeof(uint32_t));
  return true;
}

static inline void xor_free_buffer(xor_setbuffer_t *buffer) {
  free(buffer->counts);
  free(buffer->buffer);
  buffer->counts = NULL;
  buffer->buffer = NULL;
}

static inline void xor_buffered_increment_counter(uint32_t index, uint64_t hash,
                                                  xor_setbuffer_t *buffer,
                                                  xor_xorset_t *sets) {
  uint32_t slot = index >> buffer->insignificantbits;
  size_t addr = buffer->counts[slot] + (slot << buffer->insignificantbits);
  buffer->buffer[addr].index = index;
  buffer->buffer[addr].hash = hash;
  buffer->counts[slot]++;
  size_t offset = (slot << buffer->insignificantbits);
  if (buffer->counts[slot] == buffer->slotsize) {
    // must empty the buffer
    for (size_t i = offset; i < buffer->slotsize + offset; i++) {
      xor_keyindex_t ki =
          buffer->buffer[i];
      sets[ki.index].xormask ^= ki.hash;
      sets[ki.index].count++;
    }
    buffer->counts[slot] = 0;
  }
}

static inline void xor_make_buffer_current(xor_setbuffer_t *buffer,
                                           xor_xorset_t *sets, uint32_t index,
                                           xor_keyindex_t *Q, size_t *Qsize) {
  uint32_t slot = index >> buffer->insignificantbits;
  if(buffer->counts[slot] > 0) { // uncommon!
    size_t qsize = *Qsize;
    size_t offset = (slot << buffer->insignificantbits);
    for (size_t i = offset; i < buffer->counts[slot] + offset; i++) {
      xor_keyindex_t ki = buffer->buffer[i];
      sets[ki.index].xormask ^= ki.hash;
      sets[ki.index].count--;
      if (sets[ki.index].count == 1) {// this branch might be hard to predict
        ki.hash = sets[ki.index].xormask;
        Q[qsize] = ki;
        qsize += 1;
      }
    }
    *Qsize = qsize;
    buffer->counts[slot] = 0;
  }
}



static inline void xor_buffered_decrement_counter(uint32_t index, uint64_t hash,
                                                  xor_setbuffer_t *buffer,
                                                  xor_xorset_t *sets,
                                                  xor_keyindex_t *Q,
                                                  size_t *Qsize) {
  uint32_t slot = index >> buffer->insignificantbits;
  size_t addr = buffer->counts[slot] + (slot << buffer->insignificantbits);
  buffer->buffer[addr].index = index;
  buffer->buffer[addr].hash = hash;
  buffer->counts[slot]++;
  if (buffer->counts[slot] == buffer->slotsize) {
    size_t qsize = *Qsize;
    size_t offset = (slot << buffer->insignificantbits);
    for (size_t i = offset; i < buffer->counts[slot] + offset; i++) {
      xor_keyindex_t ki =
          buffer->buffer[i];
      sets[ki.index].xormask ^= ki.hash;
      sets[ki.index].count--;
      if (sets[ki.index].count == 1) {
        ki.hash = sets[ki.index].xormask;
        Q[qsize] = ki;
        qsize += 1;
      }
    }
    *Qsize = qsize;
    buffer->counts[slot] = 0;
  }
}

static inline void xor_flush_increment_buffer(xor_setbuffer_t *buffer,
                                              xor_xorset_t *sets) {
  for (uint32_t slot = 0; slot < buffer->slotcount; slot++) {
    size_t offset = (slot << buffer->insignificantbits);
    for (size_t i = offset; i < buffer->counts[slot] + offset; i++) {
      xor_keyindex_t ki =
          buffer->buffer[i];
      sets[ki.index].xormask ^= ki.hash;
      sets[ki.index].count++;
    }
    buffer->counts[slot] = 0;
  }
}

static inline void xor_flush_decrement_buffer(xor_setbuffer_t *buffer,
                                              xor_xorset_t *sets,
                                              xor_keyindex_t *Q,
                                              size_t *Qsize) {
  size_t qsize = *Qsize;
  for (uint32_t slot = 0; slot < buffer->slotcount; slot++) {
    uint32_t base = (slot << buffer->insignificantbits);
    for (size_t i = base; i < buffer->counts[slot] + base; i++) {
      xor_keyindex_t ki = buffer->buffer[i];
      sets[ki.index].xormask ^= ki.hash;
      sets[ki.index].count--;
      if (sets[ki.index].count == 1) {
        ki.hash = sets[ki.index].xormask;
        Q[qsize] = ki;
        qsize += 1;
      }
    }
    buffer->counts[slot] = 0;
  }
  *Qsize = qsize;
}

static inline uint32_t xor_flushone_decrement_buffer(xor_setbuffer_t *buffer,
                                                     xor_xorset_t *sets,
                                                     xor_keyindex_t *Q,
                                                     size_t *Qsize) {
  uint32_t bestslot = 0;
  uint32_t bestcount = buffer->counts[bestslot];
  for (uint32_t slot = 1; slot < buffer->slotcount; slot++) {
    if (buffer->counts[slot] > bestcount) {
      bestslot = slot;
      bestcount = buffer->counts[slot];
    }
  }
  uint32_t slot = bestslot;
  size_t qsize = *Qsize;
  // for(uint32_t slot = 0; slot < buffer->slotcount; slot++) {
  uint32_t base = (slot << buffer->insignificantbits);
  for (size_t i = base; i < buffer->counts[slot] + base; i++) {
    xor_keyindex_t ki = buffer->buffer[i];
    sets[ki.index].xormask ^= ki.hash;
    sets[ki.index].count--;
    if (sets[ki.index].count == 1) {
      ki.hash = sets[ki.index].xormask;
      Q[qsize] = ki;
      qsize += 1;
    }
  }
  *Qsize = qsize;
  buffer->counts[slot] = 0;
  //}
  return bestslot;
}

// Construct the filter, returns true on success, false on failure.
// The algorithm fails when there is insufficient memory.
// The caller is responsable for calling binary_fuse8_allocate(size,filter)
// before. For best performance, the caller should ensure that there are not too
// many duplicated keys.
static inline bool xor8_buffered_populate(const uint64_t *keys, uint32_t size, xor8_t *filter) {
  if(size == 0) { return false; }
  uint64_t rng_counter = 1;
  filter->seed = xor_rng_splitmix64(&rng_counter);
  size_t arrayLength = filter->blockLength * 3; // size of the backing array
  xor_setbuffer_t buffer0, buffer1, buffer2;
  size_t blockLength = filter->blockLength;
  bool ok0 = xor_init_buffer(&buffer0, blockLength);
  bool ok1 = xor_init_buffer(&buffer1, blockLength);
  bool ok2 = xor_init_buffer(&buffer2, blockLength);
  if (!ok0 || !ok1 || !ok2) {
    xor_free_buffer(&buffer0);
    xor_free_buffer(&buffer1);
    xor_free_buffer(&buffer2);
    return false;
  }

  xor_xorset_t *sets =
      (xor_xorset_t *)malloc(arrayLength * sizeof(xor_xorset_t));
  xor_xorset_t *sets0 = sets;

  xor_keyindex_t *Q =
      (xor_keyindex_t *)malloc(arrayLength * sizeof(xor_keyindex_t));

  xor_keyindex_t *stack =
      (xor_keyindex_t *)malloc(size * sizeof(xor_keyindex_t));

  if ((sets == NULL) || (Q == NULL) || (stack == NULL)) {
    xor_free_buffer(&buffer0);
    xor_free_buffer(&buffer1);
    xor_free_buffer(&buffer2);
    free(sets);
    free(Q);
    free(stack);
    return false;
  }
  xor_xorset_t *sets1 = sets + blockLength;
  xor_xorset_t *sets2 = sets + 2 * blockLength;
  xor_keyindex_t *Q0 = Q;
  xor_keyindex_t *Q1 = Q + blockLength;
  xor_keyindex_t *Q2 = Q + 2 * blockLength;

  int iterations = 0;

  while (true) {
    iterations ++;
    if(iterations > XOR_MAX_ITERATIONS) {
      // The probability of this happening is lower than the
      // the cosmic-ray probability (i.e., a cosmic ray corrupts your system),
      // but if it happens, we just fill the fingerprint with ones which
      // will flag all possible keys as 'possible', ensuring a correct result.
      memset(filter->fingerprints, ~0,  3 * filter->blockLength);
      xor_free_buffer(&buffer0);
      xor_free_buffer(&buffer1);
      xor_free_buffer(&buffer2);
      free(sets);
      free(Q);
      free(stack);
      return false;
    }
    memset(sets, 0, sizeof(xor_xorset_t) * arrayLength);
    for (size_t i = 0; i < size; i++) {
      uint64_t key = keys[i];
      xor_hashes_t hs = xor8_get_h0_h1_h2(key, filter);
      xor_buffered_increment_counter(hs.h0, hs.h, &buffer0, sets0);
      xor_buffered_increment_counter(hs.h1, hs.h, &buffer1,
                                     sets1);
      xor_buffered_increment_counter(hs.h2, hs.h, &buffer2,
                                     sets2);
    }
    xor_flush_increment_buffer(&buffer0, sets0);
    xor_flush_increment_buffer(&buffer1, sets1);
    xor_flush_increment_buffer(&buffer2, sets2);
    // todo: the flush should be sync with the detection that follows
    // scan for values with a count of one
    size_t Q0size = 0, Q1size = 0, Q2size = 0;
    for (size_t i = 0; i < filter->blockLength; i++) {
      if (sets0[i].count == 1) {
        Q0[Q0size].index = i;
        Q0[Q0size].hash = sets0[i].xormask;
        Q0size++;
      }
    }

    for (size_t i = 0; i < filter->blockLength; i++) {
      if (sets1[i].count == 1) {
        Q1[Q1size].index = i;
        Q1[Q1size].hash = sets1[i].xormask;
        Q1size++;
      }
    }
    for (size_t i = 0; i < filter->blockLength; i++) {
      if (sets2[i].count == 1) {
        Q2[Q2size].index = i;
        Q2[Q2size].hash = sets2[i].xormask;
        Q2size++;
      }
    }

    size_t stack_size = 0;
    while (Q0size + Q1size + Q2size > 0) {
      while (Q0size > 0) {
        xor_keyindex_t keyindex = Q0[--Q0size];
        size_t index = keyindex.index;
        xor_make_buffer_current(&buffer0, sets0, index, Q0, &Q0size);

        if (sets0[index].count == 0)
          continue; // not actually possible after the initial scan.
        //sets0[index].count = 0;
        uint64_t hash = keyindex.hash;
        uint32_t h1 = xor8_get_h1(hash, filter);
        uint32_t h2 = xor8_get_h2(hash, filter);

        stack[stack_size] = keyindex;
        stack_size++;
        xor_buffered_decrement_counter(h1, hash, &buffer1, sets1,
                                       Q1, &Q1size);
        xor_buffered_decrement_counter(h2, hash, &buffer2,
                                       sets2, Q2, &Q2size);
      }
      if (Q1size == 0)
        xor_flushone_decrement_buffer(&buffer1, sets1, Q1, &Q1size);

      while (Q1size > 0) {
        xor_keyindex_t keyindex = Q1[--Q1size];
        size_t index = keyindex.index;
        xor_make_buffer_current(&buffer1, sets1, index, Q1, &Q1size);

        if (sets1[index].count == 0)
          continue;
        //sets1[index].count = 0;
        uint64_t hash = keyindex.hash;
        uint32_t h0 = xor8_get_h0(hash, filter);
        uint32_t h2 = xor8_get_h2(hash, filter);
        keyindex.index += blockLength;
        stack[stack_size] = keyindex;
        stack_size++;
        xor_buffered_decrement_counter(h0, hash, &buffer0, sets0, Q0, &Q0size);
        xor_buffered_decrement_counter(h2, hash, &buffer2,
                                       sets2, Q2, &Q2size);
      }
      if (Q2size == 0)
        xor_flushone_decrement_buffer(&buffer2, sets2, Q2, &Q2size);
      while (Q2size > 0) {
        xor_keyindex_t keyindex = Q2[--Q2size];
        size_t index = keyindex.index;
        xor_make_buffer_current(&buffer2, sets2, index, Q2, &Q2size);
        if (sets2[index].count == 0)
          continue;

        //sets2[index].count = 0;
        uint64_t hash = keyindex.hash;

        uint32_t h0 = xor8_get_h0(hash, filter);
        uint32_t h1 = xor8_get_h1(hash, filter);
        keyindex.index += 2 * blockLength;

        stack[stack_size] = keyindex;
        stack_size++;
        xor_buffered_decrement_counter(h0, hash, &buffer0, sets0, Q0, &Q0size);
        xor_buffered_decrement_counter(h1, hash, &buffer1, sets1,
                                       Q1, &Q1size);
      }
      if (Q0size == 0)
        xor_flushone_decrement_buffer(&buffer0, sets0, Q0, &Q0size);
      if ((Q0size + Q1size + Q2size == 0) && (stack_size < size)) {
        // this should basically never happen
        xor_flush_decrement_buffer(&buffer0, sets0, Q0, &Q0size);
        xor_flush_decrement_buffer(&buffer1, sets1, Q1, &Q1size);
        xor_flush_decrement_buffer(&buffer2, sets2, Q2, &Q2size);
      }
    }
    if (stack_size == size) {
      // success
      break;
    }

    filter->seed = xor_rng_splitmix64(&rng_counter);
  }
  uint8_t * fingerprints0 = filter->fingerprints;
  uint8_t * fingerprints1 = filter->fingerprints + blockLength;
  uint8_t * fingerprints2 = filter->fingerprints + 2 * blockLength;

  size_t stack_size = size;
  while (stack_size > 0) {
    xor_keyindex_t ki = stack[--stack_size];
    uint64_t val = xor_fingerprint(ki.hash);
    if(ki.index < blockLength) {
      val ^= fingerprints1[xor8_get_h1(ki.hash,filter)] ^ fingerprints2[xor8_get_h2(ki.hash,filter)];
    } else if(ki.index < 2 * blockLength) {
      val ^= fingerprints0[xor8_get_h0(ki.hash,filter)] ^ fingerprints2[xor8_get_h2(ki.hash,filter)];
    } else {
      val ^= fingerprints0[xor8_get_h0(ki.hash,filter)] ^ fingerprints1[xor8_get_h1(ki.hash,filter)];
    }
    filter->fingerprints[ki.index] = val;
  }
  xor_free_buffer(&buffer0);
  xor_free_buffer(&buffer1);
  xor_free_buffer(&buffer2);

  free(sets);
  free(Q);
  free(stack);
  return true;
}

// Construct the filter, returns true on success, false on failure.
// The algorithm fails when there is insufficient memory.
// The caller is responsable for calling binary_fuse8_allocate(size,filter)
// before. For best performance, the caller should ensure that there are not too
// many duplicated keys.
static inline bool xor8_populate(const uint64_t *keys, uint32_t size, xor8_t *filter) {
  if(size == 0) { return false; }
  uint64_t rng_counter = 1;
  filter->seed = xor_rng_splitmix64(&rng_counter);
  size_t arrayLength = filter->blockLength * 3; // size of the backing array
  size_t blockLength = filter->blockLength;

  xor_xorset_t *sets =
      (xor_xorset_t *)malloc(arrayLength * sizeof(xor_xorset_t));

  xor_keyindex_t *Q =
      (xor_keyindex_t *)malloc(arrayLength * sizeof(xor_keyindex_t));

  xor_keyindex_t *stack =
      (xor_keyindex_t *)malloc(size * sizeof(xor_keyindex_t));

  if ((sets == NULL) || (Q == NULL) || (stack == NULL)) {
    free(sets);
    free(Q);
    free(stack);
    return false;
  }
  xor_xorset_t *sets0 = sets;
  xor_xorset_t *sets1 = sets + blockLength;
  xor_xorset_t *sets2 = sets + 2 * blockLength;
  xor_keyindex_t *Q0 = Q;
  xor_keyindex_t *Q1 = Q + blockLength;
  xor_keyindex_t *Q2 = Q + 2 * blockLength;

  int iterations = 0;

  while (true) {
    iterations ++;
    if(iterations > XOR_MAX_ITERATIONS) {
      // The probability of this happening is lower than the
      // the cosmic-ray probability (i.e., a cosmic ray corrupts your system),
      // but if it happens, we just fill the fingerprint with ones which
      // will flag all possible keys as 'possible', ensuring a correct result.
      memset(filter->fingerprints, ~0, 3 * filter->blockLength);
      free(sets);
      free(Q);
      free(stack);
      return false;
    }

    memset(sets, 0, sizeof(xor_xorset_t) * arrayLength);
    for (size_t i = 0; i < size; i++) {
      uint64_t key = keys[i];
      xor_hashes_t hs = xor8_get_h0_h1_h2(key, filter);
      sets0[hs.h0].xormask ^= hs.h;
      sets0[hs.h0].count++;
      sets1[hs.h1].xormask ^= hs.h;
      sets1[hs.h1].count++;
      sets2[hs.h2].xormask ^= hs.h;
      sets2[hs.h2].count++;
    }
    // todo: the flush should be sync with the detection that follows
    // scan for values with a count of one
    size_t Q0size = 0, Q1size = 0, Q2size = 0;
    for (size_t i = 0; i < filter->blockLength; i++) {
      if (sets0[i].count == 1) {
        Q0[Q0size].index = i;
        Q0[Q0size].hash = sets0[i].xormask;
        Q0size++;
      }
    }

    for (size_t i = 0; i < filter->blockLength; i++) {
      if (sets1[i].count == 1) {
        Q1[Q1size].index = i;
        Q1[Q1size].hash = sets1[i].xormask;
        Q1size++;
      }
    }
    for (size_t i = 0; i < filter->blockLength; i++) {
      if (sets2[i].count == 1) {
        Q2[Q2size].index = i;
        Q2[Q2size].hash = sets2[i].xormask;
        Q2size++;
      }
    }

    size_t stack_size = 0;
    while (Q0size + Q1size + Q2size > 0) {
      while (Q0size > 0) {
        xor_keyindex_t keyindex = Q0[--Q0size];
        size_t index = keyindex.index;
        if (sets0[index].count == 0)
          continue; // not actually possible after the initial scan.
        //sets0[index].count = 0;
        uint64_t hash = keyindex.hash;
        uint32_t h1 = xor8_get_h1(hash, filter);
        uint32_t h2 = xor8_get_h2(hash, filter);

        stack[stack_size] = keyindex;
        stack_size++;
        sets1[h1].xormask ^= hash;
        sets1[h1].count--;
        if (sets1[h1].count == 1) {
          Q1[Q1size].index = h1;
          Q1[Q1size].hash = sets1[h1].xormask;
          Q1size++;
        }
        sets2[h2].xormask ^= hash;
        sets2[h2].count--;
        if (sets2[h2].count == 1) {
          Q2[Q2size].index = h2;
          Q2[Q2size].hash = sets2[h2].xormask;
          Q2size++;
        }
      }
      while (Q1size > 0) {
        xor_keyindex_t keyindex = Q1[--Q1size];
        size_t index = keyindex.index;
        if (sets1[index].count == 0)
          continue;
        //sets1[index].count = 0;
        uint64_t hash = keyindex.hash;
        uint32_t h0 = xor8_get_h0(hash, filter);
        uint32_t h2 = xor8_get_h2(hash, filter);
        keyindex.index += blockLength;
        stack[stack_size] = keyindex;
        stack_size++;
        sets0[h0].xormask ^= hash;
        sets0[h0].count--;
        if (sets0[h0].count == 1) {
          Q0[Q0size].index = h0;
          Q0[Q0size].hash = sets0[h0].xormask;
          Q0size++;
        }
        sets2[h2].xormask ^= hash;
        sets2[h2].count--;
        if (sets2[h2].count == 1) {
          Q2[Q2size].index = h2;
          Q2[Q2size].hash = sets2[h2].xormask;
          Q2size++;
        }
      }
      while (Q2size > 0) {
        xor_keyindex_t keyindex = Q2[--Q2size];
        size_t index = keyindex.index;
        if (sets2[index].count == 0)
          continue;

        //sets2[index].count = 0;
        uint64_t hash = keyindex.hash;

        uint32_t h0 = xor8_get_h0(hash, filter);
        uint32_t h1 = xor8_get_h1(hash, filter);
        keyindex.index += 2 * blockLength;

        stack[stack_size] = keyindex;
        stack_size++;
        sets0[h0].xormask ^= hash;
        sets0[h0].count--;
        if (sets0[h0].count == 1) {
          Q0[Q0size].index = h0;
          Q0[Q0size].hash = sets0[h0].xormask;
          Q0size++;
        }
        sets1[h1].xormask ^= hash;
        sets1[h1].count--;
        if (sets1[h1].count == 1) {
          Q1[Q1size].index = h1;
          Q1[Q1size].hash = sets1[h1].xormask;
          Q1size++;
        }

      }
    }
    if (stack_size == size) {
      // success
      break;
    }

    filter->seed = xor_rng_splitmix64(&rng_counter);
  }
  uint8_t * fingerprints0 = filter->fingerprints;
  uint8_t * fingerprints1 = filter->fingerprints + blockLength;
  uint8_t * fingerprints2 = filter->fingerprints + 2 * blockLength;

  size_t stack_size = size;
  while (stack_size > 0) {
    xor_keyindex_t ki = stack[--stack_size];
    uint64_t val = xor_fingerprint(ki.hash);
    if(ki.index < blockLength) {
      val ^= fingerprints1[xor8_get_h1(ki.hash,filter)] ^ fingerprints2[xor8_get_h2(ki.hash,filter)];
    } else if(ki.index < 2 * blockLength) {
      val ^= fingerprints0[xor8_get_h0(ki.hash,filter)] ^ fingerprints2[xor8_get_h2(ki.hash,filter)];
    } else {
      val ^= fingerprints0[xor8_get_h0(ki.hash,filter)] ^ fingerprints1[xor8_get_h1(ki.hash,filter)];
    }
    filter->fingerprints[ki.index] = val;
  }

  free(sets);
  free(Q);
  free(stack);
  return true;
}


// Construct the filter, returns true on success, false on failure.
// The algorithm fails when there is insufficient memory.
// The caller is responsable for calling binary_fuse8_allocate(size,filter)
// before. For best performance, the caller should ensure that there are not too
// many duplicated keys.
static inline bool xor16_buffered_populate(const uint64_t *keys, uint32_t size, xor16_t *filter) {
  if(size == 0) { return false; }
  uint64_t rng_counter = 1;
  filter->seed = xor_rng_splitmix64(&rng_counter);
  size_t arrayLength = filter->blockLength * 3; // size of the backing array
  xor_setbuffer_t buffer0, buffer1, buffer2;
  size_t blockLength = filter->blockLength;
  bool ok0 = xor_init_buffer(&buffer0, blockLength);
  bool ok1 =  xor_init_buffer(&buffer1, blockLength);
  bool ok2 =  xor_init_buffer(&buffer2, blockLength);
  if (!ok0 || !ok1 || !ok2) {
    xor_free_buffer(&buffer0);
    xor_free_buffer(&buffer1);
    xor_free_buffer(&buffer2);
    return false;
  }

  xor_xorset_t *sets =
      (xor_xorset_t *)malloc(arrayLength * sizeof(xor_xorset_t));

  xor_keyindex_t *Q =
      (xor_keyindex_t *)malloc(arrayLength * sizeof(xor_keyindex_t));

  xor_keyindex_t *stack =
      (xor_keyindex_t *)malloc(size * sizeof(xor_keyindex_t));

  if ((sets == NULL) || (Q == NULL) || (stack == NULL)) {
    xor_free_buffer(&buffer0);
    xor_free_buffer(&buffer1);
    xor_free_buffer(&buffer2);
    free(sets);
    free(Q);
    free(stack);
    return false;
  }
  xor_xorset_t *sets0 = sets;
  xor_xorset_t *sets1 = sets + blockLength;
  xor_xorset_t *sets2 = sets + 2 * blockLength;
  xor_keyindex_t *Q0 = Q;
  xor_keyindex_t *Q1 = Q + blockLength;
  xor_keyindex_t *Q2 = Q + 2 * blockLength;

  int iterations = 0;

  while (true) {
    iterations ++;
    if(iterations > XOR_MAX_ITERATIONS) {
      // The probability of this happening is lower than the
      // the cosmic-ray probability (i.e., a cosmic ray corrupts your system),
      // but if it happens, we just fill the fingerprint with ones which
      // will flag all possible keys as 'possible', ensuring a correct result.
      memset(filter->fingerprints, ~0, 3 * filter->blockLength * sizeof(uint16_t));
      xor_free_buffer(&buffer0);
      xor_free_buffer(&buffer1);
      xor_free_buffer(&buffer2);
      free(sets);
      free(Q);
      free(stack);
      return false;
    }

    memset(sets, 0, sizeof(xor_xorset_t) * arrayLength);
    for (size_t i = 0; i < size; i++) {
      uint64_t key = keys[i];
      xor_hashes_t hs = xor16_get_h0_h1_h2(key, filter);
      xor_buffered_increment_counter(hs.h0, hs.h, &buffer0, sets0);
      xor_buffered_increment_counter(hs.h1, hs.h, &buffer1,
                                     sets1);
      xor_buffered_increment_counter(hs.h2, hs.h, &buffer2,
                                     sets2);
    }
    xor_flush_increment_buffer(&buffer0, sets0);
    xor_flush_increment_buffer(&buffer1, sets1);
    xor_flush_increment_buffer(&buffer2, sets2);
    // todo: the flush should be sync with the detection that follows
    // scan for values with a count of one
    size_t Q0size = 0, Q1size = 0, Q2size = 0;
    for (size_t i = 0; i < filter->blockLength; i++) {
      if (sets0[i].count == 1) {
        Q0[Q0size].index = i;
        Q0[Q0size].hash = sets0[i].xormask;
        Q0size++;
      }
    }

    for (size_t i = 0; i < filter->blockLength; i++) {
      if (sets1[i].count == 1) {
        Q1[Q1size].index = i;
        Q1[Q1size].hash = sets1[i].xormask;
        Q1size++;
      }
    }
    for (size_t i = 0; i < filter->blockLength; i++) {
      if (sets2[i].count == 1) {
        Q2[Q2size].index = i;
        Q2[Q2size].hash = sets2[i].xormask;
        Q2size++;
      }
    }

    size_t stack_size = 0;
    while (Q0size + Q1size + Q2size > 0) {
      while (Q0size > 0) {
        xor_keyindex_t keyindex = Q0[--Q0size];
        size_t index = keyindex.index;
        xor_make_buffer_current(&buffer0, sets0, index, Q0, &Q0size);

        if (sets0[index].count == 0)
          continue; // not actually possible after the initial scan.
        //sets0[index].count = 0;
        uint64_t hash = keyindex.hash;
        uint32_t h1 = xor16_get_h1(hash, filter);
        uint32_t h2 = xor16_get_h2(hash, filter);

        stack[stack_size] = keyindex;
        stack_size++;
        xor_buffered_decrement_counter(h1, hash, &buffer1, sets1,
                                       Q1, &Q1size);
        xor_buffered_decrement_counter(h2, hash, &buffer2,
                                       sets2, Q2, &Q2size);
      }
      if (Q1size == 0)
        xor_flushone_decrement_buffer(&buffer1, sets1, Q1, &Q1size);

      while (Q1size > 0) {
        xor_keyindex_t keyindex = Q1[--Q1size];
        size_t index = keyindex.index;
        xor_make_buffer_current(&buffer1, sets1, index, Q1, &Q1size);

        if (sets1[index].count == 0)
          continue;
        //sets1[index].count = 0;
        uint64_t hash = keyindex.hash;
        uint32_t h0 = xor16_get_h0(hash, filter);
        uint32_t h2 = xor16_get_h2(hash, filter);
        keyindex.index += blockLength;
        stack[stack_size] = keyindex;
        stack_size++;
        xor_buffered_decrement_counter(h0, hash, &buffer0, sets0, Q0, &Q0size);
        xor_buffered_decrement_counter(h2, hash, &buffer2,
                                       sets2, Q2, &Q2size);
      }
      if (Q2size == 0)
        xor_flushone_decrement_buffer(&buffer2, sets2, Q2, &Q2size);
      while (Q2size > 0) {
        xor_keyindex_t keyindex = Q2[--Q2size];
        size_t index = keyindex.index;
        xor_make_buffer_current(&buffer2, sets2, index, Q2, &Q2size);
        if (sets2[index].count == 0)
          continue;

        //sets2[index].count = 0;
        uint64_t hash = keyindex.hash;

        uint32_t h0 = xor16_get_h0(hash, filter);
        uint32_t h1 = xor16_get_h1(hash, filter);
        keyindex.index += 2 * blockLength;

        stack[stack_size] = keyindex;
        stack_size++;
        xor_buffered_decrement_counter(h0, hash, &buffer0, sets0, Q0, &Q0size);
        xor_buffered_decrement_counter(h1, hash, &buffer1, sets1,
                                       Q1, &Q1size);
      }
      if (Q0size == 0)
        xor_flushone_decrement_buffer(&buffer0, sets0, Q0, &Q0size);
      if ((Q0size + Q1size + Q2size == 0) && (stack_size < size)) {
        // this should basically never happen
        xor_flush_decrement_buffer(&buffer0, sets0, Q0, &Q0size);
        xor_flush_decrement_buffer(&buffer1, sets1, Q1, &Q1size);
        xor_flush_decrement_buffer(&buffer2, sets2, Q2, &Q2size);
      }
    }
    if (stack_size == size) {
      // success
      break;
    }

    filter->seed = xor_rng_splitmix64(&rng_counter);
  }
  uint16_t * fingerprints0 = filter->fingerprints;
  uint16_t * fingerprints1 = filter->fingerprints + blockLength;
  uint16_t * fingerprints2 = filter->fingerprints + 2 * blockLength;

  size_t stack_size = size;
  while (stack_size > 0) {
    xor_keyindex_t ki = stack[--stack_size];
    uint64_t val = xor_fingerprint(ki.hash);
    if(ki.index < blockLength) {
      val ^= fingerprints1[xor16_get_h1(ki.hash,filter)] ^ fingerprints2[xor16_get_h2(ki.hash,filter)];
    } else if(ki.index < 2 * blockLength) {
      val ^= fingerprints0[xor16_get_h0(ki.hash,filter)] ^ fingerprints2[xor16_get_h2(ki.hash,filter)];
    } else {
      val ^= fingerprints0[xor16_get_h0(ki.hash,filter)] ^ fingerprints1[xor16_get_h1(ki.hash,filter)];
    }
    filter->fingerprints[ki.index] = val;
  }
  xor_free_buffer(&buffer0);
  xor_free_buffer(&buffer1);
  xor_free_buffer(&buffer2);

  free(sets);
  free(Q);
  free(stack);
  return true;
}



// Construct the filter, returns true on success, false on failure.
// The algorithm fails when there is insufficient memory.
// The caller is responsable for calling binary_fuse8_allocate(size,filter)
// before. For best performance, the caller should ensure that there are not too
// many duplicated keys.
static inline bool xor16_populate(const uint64_t *keys, uint32_t size, xor16_t *filter) {
  if(size == 0) { return false; }
  uint64_t rng_counter = 1;
  filter->seed = xor_rng_splitmix64(&rng_counter);
  size_t arrayLength = filter->blockLength * 3; // size of the backing array
  size_t blockLength = filter->blockLength;

  xor_xorset_t *sets =
      (xor_xorset_t *)malloc(arrayLength * sizeof(xor_xorset_t));

  xor_keyindex_t *Q =
      (xor_keyindex_t *)malloc(arrayLength * sizeof(xor_keyindex_t));

  xor_keyindex_t *stack =
      (xor_keyindex_t *)malloc(size * sizeof(xor_keyindex_t));

  if ((sets == NULL) || (Q == NULL) || (stack == NULL)) {
    free(sets);
    free(Q);
    free(stack);
    return false;
  }
  xor_xorset_t *sets0 = sets;
  xor_xorset_t *sets1 = sets + blockLength;
  xor_xorset_t *sets2 = sets + 2 * blockLength;

  xor_keyindex_t *Q0 = Q;
  xor_keyindex_t *Q1 = Q + blockLength;
  xor_keyindex_t *Q2 = Q + 2 * blockLength;

  int iterations = 0;

  while (true) {
    iterations ++;
    if(iterations > XOR_MAX_ITERATIONS) {
      // The probability of this happening is lower than the
      // the cosmic-ray probability (i.e., a cosmic ray corrupts your system),
      // but if it happens, we just fill the fingerprint with ones which
      // will flag all possible keys as 'possible', ensuring a correct result.
      memset(filter->fingerprints, ~0, 3 * filter->blockLength * sizeof(uint16_t));
      free(sets);
      free(Q);
      free(stack);
      return true;
    }

    memset(sets, 0, sizeof(xor_xorset_t) * arrayLength);
    for (size_t i = 0; i < size; i++) {
      uint64_t key = keys[i];
      xor_hashes_t hs = xor16_get_h0_h1_h2(key, filter);
      sets0[hs.h0].xormask ^= hs.h;
      sets0[hs.h0].count++;
      sets1[hs.h1].xormask ^= hs.h;
      sets1[hs.h1].count++;
      sets2[hs.h2].xormask ^= hs.h;
      sets2[hs.h2].count++;
    }
    // todo: the flush should be sync with the detection that follows
    // scan for values with a count of one
    size_t Q0size = 0, Q1size = 0, Q2size = 0;
    for (size_t i = 0; i < filter->blockLength; i++) {
      if (sets0[i].count == 1) {
        Q0[Q0size].index = i;
        Q0[Q0size].hash = sets0[i].xormask;
        Q0size++;
      }
    }

    for (size_t i = 0; i < filter->blockLength; i++) {
      if (sets1[i].count == 1) {
        Q1[Q1size].index = i;
        Q1[Q1size].hash = sets1[i].xormask;
        Q1size++;
      }
    }
    for (size_t i = 0; i < filter->blockLength; i++) {
      if (sets2[i].count == 1) {
        Q2[Q2size].index = i;
        Q2[Q2size].hash = sets2[i].xormask;
        Q2size++;
      }
    }

    size_t stack_size = 0;
    while (Q0size + Q1size + Q2size > 0) {
      while (Q0size > 0) {
        xor_keyindex_t keyindex = Q0[--Q0size];
        size_t index = keyindex.index;
        if (sets0[index].count == 0)
          continue; // not actually possible after the initial scan.
        //sets0[index].count = 0;
        uint64_t hash = keyindex.hash;
        uint32_t h1 = xor16_get_h1(hash, filter);
        uint32_t h2 = xor16_get_h2(hash, filter);

        stack[stack_size] = keyindex;
        stack_size++;
        sets1[h1].xormask ^= hash;
        sets1[h1].count--;
        if (sets1[h1].count == 1) {
          Q1[Q1size].index = h1;
          Q1[Q1size].hash = sets1[h1].xormask;
          Q1size++;
        }
        sets2[h2].xormask ^= hash;
        sets2[h2].count--;
        if (sets2[h2].count == 1) {
          Q2[Q2size].index = h2;
          Q2[Q2size].hash = sets2[h2].xormask;
          Q2size++;
        }
      }
      while (Q1size > 0) {
        xor_keyindex_t keyindex = Q1[--Q1size];
        size_t index = keyindex.index;
        if (sets1[index].count == 0)
          continue;
        //sets1[index].count = 0;
        uint64_t hash = keyindex.hash;
        uint32_t h0 = xor16_get_h0(hash, filter);
        uint32_t h2 = xor16_get_h2(hash, filter);
        keyindex.index += blockLength;
        stack[stack_size] = keyindex;
        stack_size++;
        sets0[h0].xormask ^= hash;
        sets0[h0].count--;
        if (sets0[h0].count == 1) {
          Q0[Q0size].index = h0;
          Q0[Q0size].hash = sets0[h0].xormask;
          Q0size++;
        }
        sets2[h2].xormask ^= hash;
        sets2[h2].count--;
        if (sets2[h2].count == 1) {
          Q2[Q2size].index = h2;
          Q2[Q2size].hash = sets2[h2].xormask;
          Q2size++;
        }
      }
      while (Q2size > 0) {
        xor_keyindex_t keyindex = Q2[--Q2size];
        size_t index = keyindex.index;
        if (sets2[index].count == 0)
          continue;

        //sets2[index].count = 0;
        uint64_t hash = keyindex.hash;

        uint32_t h0 = xor16_get_h0(hash, filter);
        uint32_t h1 = xor16_get_h1(hash, filter);
        keyindex.index += 2 * blockLength;

        stack[stack_size] = keyindex;
        stack_size++;
        sets0[h0].xormask ^= hash;
        sets0[h0].count--;
        if (sets0[h0].count == 1) {
          Q0[Q0size].index = h0;
          Q0[Q0size].hash = sets0[h0].xormask;
          Q0size++;
        }
        sets1[h1].xormask ^= hash;
        sets1[h1].count--;
        if (sets1[h1].count == 1) {
          Q1[Q1size].index = h1;
          Q1[Q1size].hash = sets1[h1].xormask;
          Q1size++;
        }

      }
    }
    if (stack_size == size) {
      // success
      break;
    }

    filter->seed = xor_rng_splitmix64(&rng_counter);
  }
  uint16_t * fingerprints0 = filter->fingerprints;
  uint16_t * fingerprints1 = filter->fingerprints + blockLength;
  uint16_t * fingerprints2 = filter->fingerprints + 2 * blockLength;

  size_t stack_size = size;
  while (stack_size > 0) {
    xor_keyindex_t ki = stack[--stack_size];
    uint64_t val = xor_fingerprint(ki.hash);
    if(ki.index < blockLength) {
      val ^= fingerprints1[xor16_get_h1(ki.hash,filter)] ^ fingerprints2[xor16_get_h2(ki.hash,filter)];
    } else if(ki.index < 2 * blockLength) {
      val ^= fingerprints0[xor16_get_h0(ki.hash,filter)] ^ fingerprints2[xor16_get_h2(ki.hash,filter)];
    } else {
      val ^= fingerprints0[xor16_get_h0(ki.hash,filter)] ^ fingerprints1[xor16_get_h1(ki.hash,filter)];
    }
    filter->fingerprints[ki.index] = val;
  }

  free(sets);
  free(Q);
  free(stack);
  return true;
}



#endif
