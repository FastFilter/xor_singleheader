#include "binaryfusefilter.h"
#include "xorfilter.h"
#include <assert.h>

#define FNAM(type, action) type##_##action
#define GFNAM(type, action) type##_##action##_gen

#define F1(t, a, rt, t1, p1) rt GFNAM(t, a)(t1 p1) { return FNAM(t, a)(p1); }
#define F2(t, a, rt, t1, p1, t2, p2) rt GFNAM(t, a)(t1 p1, t2 p2) { return FNAM(t, a)(p1, p2); }
#define F3(t, a, rt, t1, p1, t2, p2, t3, p3) rt GFNAM(t, a)(t1 p1, t2 p2, t3 p3) { return FNAM(t, a)(p1, p2, p3); }
// map 3-argument _gen to 2-argument, discarding last
#define F32(t, a, rt, t1, p1, t2, p2, t3, p3) rt GFNAM(t, a)(t1 p1, t2 p2, t3 p3) { (void)p3; return FNAM(t, a)(p1, p2); }
// void return, ignore return value
#define F3V(t, a, rt, t1, p1, t2, p2, t3, p3) rt GFNAM(t, a)(t1 p1, t2 p2, t3 p3) { (void)FNAM(t, a)(p1, p2, p3); }

#define GEN_THUNKS(ftype)                                                                          \
  F2(ftype, allocate, bool, uint32_t, size, void*, filter)                                         \
  F1(ftype, free, void, void*, filter)                                                             \
  F1(ftype, size_in_bytes, size_t, const void*, filter)                                            \
  F1(ftype, serialization_bytes, size_t, void*, filter)                                            \
  F32(ftype, serialize, void, void*, filter, char*, buffer, size_t, len)                           \
  F32(ftype, deserialize, bool, void*, filter, const char*, buffer, size_t, len)                    \
  F3(ftype, populate, bool, uint64_t*, keys, uint32_t, size, void*, filter)                        \
  F2(ftype, contain, bool, uint64_t, key, const void*, filter)                                     \
  F1(ftype, pack_bytes, size_t, void*, filter)                                                     \
  F3V(ftype, pack, void, void*, filter, char*, buffer, size_t, len)                                  \
  F3(ftype, unpack, bool, void*, filter, const char*, buffer, size_t, len)


GEN_THUNKS(xor8)
GEN_THUNKS(xor16)
GEN_THUNKS(binary_fuse8)
GEN_THUNKS(binary_fuse16)

F3(xor8, buffered_populate, bool, uint64_t*, keys, uint32_t, size, void*, filter)
F3(xor16, buffered_populate, bool, uint64_t*, keys, uint32_t, size, void*, filter)

bool test(size_t size, size_t repeated_size, void *filter,
          bool(*allocate)(uint32_t size, void *filter),
          void (*free_filter)(void *filter),
          size_t (*size_in_bytes)(const void *filter),
          size_t (*serialization_bytes)(void *filter),
          void (*serialize)(void *filter, char *buffer, size_t len),
          bool (*deserialize)(void *filter, const char *buffer, size_t len),
          bool (*populate)(uint64_t *keys, uint32_t size, void *filter),
          bool (*contain)(uint64_t key, const void *filter)) {
  allocate((uint32_t)size, filter);
  // we need some set of values
  uint64_t *big_set = (uint64_t *)malloc(sizeof(uint64_t) * size);
  for (size_t i = 0; i < size - repeated_size; i++) {
    big_set[i] = i; // we use contiguous values
  }
  for (size_t i = 0; i < repeated_size; i++) {
    big_set[size - i - 1] = i; // we use contiguous values
  }
  // we construct the filter
  if(!populate(big_set, (uint32_t)size, filter)) { return false; }
  for (size_t i = 0; i < size; i++) {
    if (!contain(big_set[i], filter)) {
      printf("bug!\n");
      return false;
    }
  }

  size_t buffer_size = serialization_bytes(filter);
  char *buffer = (char*)malloc(buffer_size);
  serialize(filter, buffer, buffer_size);
  free_filter(filter);
  deserialize(filter, buffer, buffer_size);
  free(buffer);
  for (size_t i = 0; i < size; i++) {
    if (!(contain)(big_set[i], filter)) {
      printf("bug!\n");
      return false;
    }
  }
  
  size_t random_matches = 0;
  size_t trials = 10000000;
  for (size_t i = 0; i < trials; i++) {
    uint64_t random_key = ((uint64_t)rand() << 32U) + (uint64_t)rand();
    if (contain(random_key, filter)) {
      if (random_key >= size) {
        random_matches++;
      }
    }
  }
  double fpp = (double)random_matches * 1.0 / (double)trials;
  printf(" fpp %3.5f (estimated) \n", fpp);
  size_t core_size = size_in_bytes(filter);
  printf(" size in-core %zu wire %zu\n", core_size, buffer_size);
  double cbpe = (double)core_size * 8.0 / (double)size;
  double wbpe = (double)buffer_size * 8.0 / (double)size;
  printf(" bits per entry in-core %3.2f wire %3.2f\n", cbpe, wbpe);
  double bound = - log(fpp)/log(2);
  printf(" bits per entry %3.2f (theoretical lower bound)\n", bound);
  printf(" efficiency ratio in-core %3.3f wire %3.3f\n", cbpe/bound, wbpe/bound);
  free_filter(filter);
  free(big_set);
  return true;
}

bool testbufferedxor8(size_t size) {
  printf("testing buffered xor8\n");
  xor8_t filter;
  return test(size, 0, &filter,
              xor8_allocate_gen,
              xor8_free_gen,
              xor8_size_in_bytes_gen,
              xor8_serialization_bytes_gen,
              xor8_serialize_gen,
              xor8_deserialize_gen,
              xor8_buffered_populate_gen,
              xor8_contain_gen);
}


bool testxor8(size_t size) {
  printf("testing xor8\n");
  xor8_t filter;
  return test(size, 0, &filter,
              xor8_allocate_gen,
              xor8_free_gen,
              xor8_size_in_bytes_gen,
              xor8_serialization_bytes_gen,
              xor8_serialize_gen,
              xor8_deserialize_gen,
              xor8_populate_gen,
              xor8_contain_gen);
}

bool testxor16(size_t size) {
  printf("testing xor16\n");
  xor16_t filter;
  return test(size, 0, &filter,
              xor16_allocate_gen,
              xor16_free_gen,
              xor16_size_in_bytes_gen,
              xor16_serialization_bytes_gen,
              xor16_serialize_gen,
              xor16_deserialize_gen,
              xor16_populate_gen,
              xor16_contain_gen);
}


bool testxor8pack(size_t size) {
  printf("testing xor8 pack/unpack\n");
  xor8_t filter;
  return test(size, 0, &filter,
              xor8_allocate_gen,
              xor8_free_gen,
              xor8_size_in_bytes_gen,
              xor8_pack_bytes_gen,
              xor8_pack_gen,
              xor8_unpack_gen,
              xor8_populate_gen,
              xor8_contain_gen);
}

bool testxor16pack(size_t size) {
  printf("testing xor16 pack/unpack\n");
  xor8_t filter;
  return test(size, 0, &filter,
              xor16_allocate_gen,
              xor16_free_gen,
              xor16_size_in_bytes_gen,
              xor16_pack_bytes_gen,
              xor16_pack_gen,
              xor16_unpack_gen,
              xor16_populate_gen,
              xor16_contain_gen);
}



bool testbufferedxor16(size_t size) {
  printf("testing buffered xor16\n");
  xor16_t filter;
  return test(size, 0, &filter,
              xor16_allocate_gen,
              xor16_free_gen,
              xor16_size_in_bytes_gen,
              xor16_serialization_bytes_gen,
              xor16_serialize_gen,
              xor16_deserialize_gen,
              xor16_buffered_populate_gen,
              xor16_contain_gen);
}

bool testbinaryfuse8(size_t size, size_t repeated_size) {
  printf("testing binary fuse8 with size %zu and %zu duplicates\n", size, repeated_size);
  binary_fuse8_t filter;

  // size serialization test
  binary_fuse8_allocate((uint32_t)size, &filter);
  uint64_t *big_set = (uint64_t *)malloc(sizeof(uint64_t) * size);
  for (size_t i = 0; i < size; i++) {
    big_set[i] = i;
  }
  if (!binary_fuse8_populate(big_set, (uint32_t)size, &filter)) {
    return false;
  }
  free(big_set);

  size_t buffer_size = binary_fuse8_serialization_bytes(&filter);
  char *buffer = (char *)malloc(buffer_size);
  binary_fuse8_serialize(&filter, buffer);
  binary_fuse8_free(&filter);
  binary_fuse8_deserialize(&filter, buffer);

  if (filter.Size != size) {
    printf("size not (de-)serialized correctly, found %d, expected %zu.",
           filter.Size, size);
    free(buffer);
    binary_fuse8_free(&filter);
    return false;
  }
  free(buffer);
  binary_fuse8_free(&filter);
  // end of size serialization test

  return test(size, repeated_size, &filter,
              binary_fuse8_allocate_gen,
              binary_fuse8_free_gen,
              binary_fuse8_size_in_bytes_gen,
              binary_fuse8_serialization_bytes_gen,
              binary_fuse8_serialize_gen,
              binary_fuse8_deserialize_gen,
              binary_fuse8_populate_gen,
              binary_fuse8_contain_gen);
}

bool testbinaryfuse16(size_t size, size_t repeated_size) {
  printf("testing binary fuse16 with size %zu and %zu duplicates\n", size, repeated_size);
  binary_fuse16_t filter;

  // size serialization test
  binary_fuse16_allocate((uint32_t)size, &filter);
  uint64_t *big_set = (uint64_t *)malloc(sizeof(uint64_t) * size);
  for (size_t i = 0; i < size; i++) {
    big_set[i] = i;
  }
  if (!binary_fuse16_populate(big_set, (uint32_t)size, &filter)) {
    return false;
  }
  free(big_set);

  size_t buffer_size = binary_fuse16_serialization_bytes(&filter);
  char *buffer = (char *)malloc(buffer_size);
  binary_fuse16_serialize(&filter, buffer);
  binary_fuse16_free(&filter);
  binary_fuse16_deserialize(&filter, buffer);

  if (filter.Size != size) {
    printf("size not (de-)serialized correctly, found %d, expected %zu.",
           filter.Size, size);
    free(buffer);
    binary_fuse16_free(&filter);
    return false;
  }

  free(buffer);
  binary_fuse16_free(&filter);
  // end of size serialization test

  return test(size, repeated_size, &filter,
              binary_fuse16_allocate_gen,
              binary_fuse16_free_gen,
              binary_fuse16_size_in_bytes_gen,
              binary_fuse16_serialization_bytes_gen,
              binary_fuse16_serialize_gen,
              binary_fuse16_deserialize_gen,
              binary_fuse16_populate_gen,
              binary_fuse16_contain_gen);
}


bool testbinaryfuse8pack(size_t size, size_t repeated_size) {
  printf("testing binary fuse8 pack/unpack with size %zu and %zu duplicates\n", size, repeated_size);
  binary_fuse8_t filter;
  return test(size, repeated_size, &filter,
              binary_fuse8_allocate_gen,
              binary_fuse8_free_gen,
              binary_fuse8_size_in_bytes_gen,
              binary_fuse8_pack_bytes_gen,
              binary_fuse8_pack_gen,
              binary_fuse8_unpack_gen,
              binary_fuse8_populate_gen,
              binary_fuse8_contain_gen);
}

bool testbinaryfuse16pack(size_t size, size_t repeated_size) {
  printf("testing binary fuse16 pack/unpack with size %zu and %zu duplicates\n", size, repeated_size);
  binary_fuse16_t filter;
  return test(size, repeated_size, &filter,
              binary_fuse16_allocate_gen,
              binary_fuse16_free_gen,
              binary_fuse16_size_in_bytes_gen,
              binary_fuse16_pack_bytes_gen,
              binary_fuse16_pack_gen,
              binary_fuse16_unpack_gen,
              binary_fuse16_populate_gen,
              binary_fuse16_contain_gen);
}

void failure_rate_binary_fuse16() {
  printf("testing binary fuse16 for failure rate\n");
  // we construct many 5000-long input cases and check the probability of failure.
  size_t size = 5000;
  uint64_t *big_set = (uint64_t *)malloc(sizeof(uint64_t) * size);
  binary_fuse16_t filter;
  binary_fuse16_allocate((uint32_t)size, &filter);
  size_t failure = 0;
  size_t total_trials = 1000000;

  for(size_t trial = 0; trial <= 1000; trial++) {
    for (size_t i = 0; i < size; i++) {
      big_set[i] = (uint64_t)rand() + (((uint64_t) rand()) << 32U);
    }
    if(!binary_fuse16_populate(big_set, (uint32_t)size, &filter)) {
      failure++;
    }
  }
  printf("failures %zu out of %zu\n\n", failure, total_trials);
  binary_fuse16_free(&filter);
  free(big_set);
}

// test code from the example in the README
void readme_pack() {
  binary_fuse16_t filter = {0};
  if (! binary_fuse16_allocate(64, &filter)) {
    printf("allocation failed\n");
    return;
  }

  // begin example snippet
  size_t buffer_size = binary_fuse16_pack_bytes(&filter);
  char *buffer = (char*)malloc(buffer_size);
  if (binary_fuse16_pack(&filter, buffer, buffer_size) != buffer_size) {
    printf("pack failed\n");
    free(buffer);
    return;
  }
  binary_fuse16_free(&filter);
  if (! binary_fuse16_unpack(&filter, buffer, buffer_size)) {
    printf("unpack failed\n");
  }
  free(buffer);
  // end example snippet

  binary_fuse16_free(&filter);
}

int main() {
  readme_pack();
  failure_rate_binary_fuse16();
  for(size_t size = 1000; size <= 1000000; size *= 300) {
    printf("== size = %zu \n", size);
    if(!testbinaryfuse8(size, 0)) { abort(); }
    printf("\n");
    if(!testbinaryfuse16(size, 0)) { abort(); }
    printf("\n");
    if(!testbinaryfuse8pack(size, 0)) { abort(); }
    printf("\n");
    if(!testbinaryfuse16pack(size, 0)) { abort(); }
    printf("\n");
    if(!testbinaryfuse8(size, 10)) { abort(); }
    printf("\n");
    if(!testbinaryfuse16(size, 10)) { abort(); }
    printf("\n");
    if(!testbufferedxor8(size)) { abort(); }
    printf("\n");
    if(!testbufferedxor16(size)) { abort(); }
    printf("\n");
    if(!testxor8(size)) { abort(); }
    printf("\n");
    if(!testxor16(size)) { abort(); }
    printf("\n");
    if(!testxor8pack(size)) { abort(); }
    printf("\n");
    if(!testxor16pack(size)) { abort(); }
    printf("\n");
    printf("======\n");
  }

  // test small edge-case binary fuse input sizes
  if(!testbinaryfuse8(0, 0)) { abort(); }
  if(!testbinaryfuse8(1, 0)) { abort(); }
  if(!testbinaryfuse8(2, 0)) { abort(); }
  if(!testbinaryfuse16(0, 0)) { abort(); }
  if(!testbinaryfuse16(1, 0)) { abort(); }
  if(!testbinaryfuse16(2, 0)) { abort(); }
}
