#include "binaryfusefilter.h"
#include "xorfilter.h"
#include <assert.h>

// generic function dispatch

bool gen_xor8_allocate(uint32_t size, void *filter) { return xor8_allocate(size, filter); }
bool gen_xor16_allocate(uint32_t size, void *filter) { return xor16_allocate(size, filter); }
bool gen_binary_fuse8_allocate(uint32_t size, void *filter) { return binary_fuse8_allocate(size, filter); }
bool gen_binary_fuse16_allocate(uint32_t size, void *filter) { return binary_fuse16_allocate(size, filter); }

void gen_xor8_free(void *filter) { xor8_free(filter); }
void gen_xor16_free(void *filter) { xor16_free(filter); }
void gen_binary_fuse8_free(void *filter) { binary_fuse8_free(filter); }
void gen_binary_fuse16_free(void *filter) { binary_fuse16_free(filter); }

size_t gen_xor8_size_in_bytes(const void *filter) { return xor8_size_in_bytes(filter); }
size_t gen_xor16_size_in_bytes(const void *filter) { return xor16_size_in_bytes(filter); }
size_t gen_binary_fuse8_size_in_bytes(const void *filter) { return binary_fuse8_size_in_bytes(filter); }
size_t gen_binary_fuse16_size_in_bytes(const void *filter) { return binary_fuse16_size_in_bytes(filter); }

size_t gen_xor8_serialization_bytes(void *filter) { return xor8_serialization_bytes(filter); }
size_t gen_xor16_serialization_bytes(void *filter) { return xor16_serialization_bytes(filter); }
size_t gen_binary_fuse8_serialization_bytes(void *filter) { return binary_fuse8_serialization_bytes(filter); }
size_t gen_binary_fuse16_serialization_bytes(void *filter) { return binary_fuse16_serialization_bytes(filter); }

void gen_xor8_serialize(void *filter, char *buffer) { xor8_serialize(filter, buffer); }
void gen_xor16_serialize(void *filter, char *buffer) { xor16_serialize(filter, buffer); }
void gen_binary_fuse8_serialize(void *filter, char *buffer) { binary_fuse8_serialize(filter, buffer); }
void gen_binary_fuse16_serialize(void *filter, char *buffer) { binary_fuse16_serialize(filter, buffer); }

bool gen_xor8_deserialize(void *filter, const char *buffer) { return xor8_deserialize(filter, buffer); }
bool gen_xor16_deserialize(void *filter, const char *buffer) { return xor16_deserialize(filter, buffer); }
bool gen_binary_fuse8_deserialize(void *filter, const char *buffer) { return binary_fuse8_deserialize(filter, buffer); }
bool gen_binary_fuse16_deserialize(void *filter, const char *buffer) { return binary_fuse16_deserialize(filter, buffer); }

bool gen_xor8_populate(uint64_t *keys, uint32_t size, void *filter) { return xor8_populate(keys, size, filter); }
bool gen_xor8_buffered_populate(uint64_t *keys, uint32_t size, void *filter) { return xor8_buffered_populate(keys, size, filter); }
bool gen_xor16_populate(uint64_t *keys, uint32_t size, void *filter) { return xor16_populate(keys, size, filter); }
bool gen_xor16_buffered_populate(uint64_t *keys, uint32_t size, void *filter) { return xor16_buffered_populate(keys, size, filter); }
bool gen_binary_fuse8_populate(uint64_t *keys, uint32_t size, void *filter) { return binary_fuse8_populate(keys, size, filter); }
bool gen_binary_fuse16_populate(uint64_t *keys, uint32_t size, void *filter) { return binary_fuse16_populate(keys, size, filter); }

bool gen_xor8_contain(uint64_t key, const void *filter) { return xor8_contain(key, filter); }
bool gen_xor16_contain(uint64_t key, const void *filter) { return xor16_contain(key, filter); }
bool gen_binary_fuse8_contain(uint64_t key, const void *filter) { return binary_fuse8_contain(key, filter); }
bool gen_binary_fuse16_contain(uint64_t key, const void *filter) { return binary_fuse16_contain(key, filter); }

typedef bool (*allocate_fpt)(uint32_t size, void *filter);
typedef void (*free_fpt)(void *filter);
typedef size_t (*size_in_bytes_fpt)(const void *filter);
typedef size_t (*serialization_bytes_fpt)(void *filter);
typedef void (*serialize_fpt)(void *filter, char *buffer);
typedef bool (*deserialize_fpt)(void *filter, const char *buffer);
typedef bool (*populate_fpt)(uint64_t *keys, uint32_t size, void *filter);
typedef bool (*contain_fpt)(uint64_t key, const void *filter);

// generic test runner

bool test(size_t size, size_t repeated_size, void *filter,
          allocate_fpt allocate,
          free_fpt free_filter,
          size_in_bytes_fpt size_in_bytes,
          serialization_bytes_fpt serialization_bytes,
          serialize_fpt serialize,
          deserialize_fpt deserialize,
          populate_fpt populate,
          contain_fpt contain) {
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
  serialize(filter, buffer);
  free_filter(filter);
  deserialize(filter, buffer);
  free(buffer);
  for (size_t i = 0; i < size; i++) {
    if (!contain(big_set[i], filter)) {
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
  double bpe = (double)size_in_bytes(filter) * 8.0 / (double)size;
  printf(" bits per entry %3.2f\n", bpe);
  printf(" bits per entry %3.2f (theoretical lower bound)\n", - log(fpp)/log(2));
  printf(" efficiency ratio %3.3f \n", bpe /(- log(fpp)/log(2)));
  free_filter(filter);
  free(big_set);
  return true;
}

bool testbufferedxor8(size_t size) {
  printf("testing buffered xor8\n");
  xor8_t filter;
  return test(size, 0, &filter,
              gen_xor8_allocate,
              gen_xor8_free,
              gen_xor8_size_in_bytes,
              gen_xor8_serialization_bytes,
              gen_xor8_serialize,
              gen_xor8_deserialize,
              gen_xor8_buffered_populate,
              gen_xor8_contain);
}


bool testxor8(size_t size) {
  printf("testing xor8\n");
  xor8_t filter;
  return test(size, 0, &filter,
              gen_xor8_allocate,
              gen_xor8_free,
              gen_xor8_size_in_bytes,
              gen_xor8_serialization_bytes,
              gen_xor8_serialize,
              gen_xor8_deserialize,
              gen_xor8_populate,
              gen_xor8_contain);
}

bool testxor16(size_t size) {
  printf("testing xor16\n");
  xor16_t filter;
  return test(size, 0, &filter,
              gen_xor16_allocate,
              gen_xor16_free,
              gen_xor16_size_in_bytes,
              gen_xor16_serialization_bytes,
              gen_xor16_serialize,
              gen_xor16_deserialize,
              gen_xor16_populate,
              gen_xor16_contain);
}



bool testbufferedxor16(size_t size) {
  printf("testing buffered xor16\n");
  xor16_t filter;
  return test(size, 0, &filter,
              gen_xor16_allocate,
              gen_xor16_free,
              gen_xor16_size_in_bytes,
              gen_xor16_serialization_bytes,
              gen_xor16_serialize,
              gen_xor16_deserialize,
              gen_xor16_buffered_populate,
              gen_xor16_contain);
}

bool testbinaryfuse8(size_t size, size_t repeated_size) {
  printf("testing binary fuse8 with size %zu and %zu duplicates\n", size, repeated_size);
  binary_fuse8_t filter;
  return test(size, repeated_size, &filter,
              gen_binary_fuse8_allocate,
              gen_binary_fuse8_free,
              gen_binary_fuse8_size_in_bytes,
              gen_binary_fuse8_serialization_bytes,
              gen_binary_fuse8_serialize,
              gen_binary_fuse8_deserialize,
              gen_binary_fuse8_populate,
              gen_binary_fuse8_contain);
}



bool testbinaryfuse16(size_t size, size_t repeated_size) {
  printf("testing binary fuse16 with size %zu and %zu duplicates\n", size, repeated_size);
  binary_fuse16_t filter;
  return test(size, repeated_size, &filter,
              gen_binary_fuse16_allocate,
              gen_binary_fuse16_free,
              gen_binary_fuse16_size_in_bytes,
              gen_binary_fuse16_serialization_bytes,
              gen_binary_fuse16_serialize,
              gen_binary_fuse16_deserialize,
              gen_binary_fuse16_populate,
              gen_binary_fuse16_contain);
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

int main() {
  failure_rate_binary_fuse16();
  for(size_t size = 1000; size <= 1000000; size *= 300) {
    printf("== size = %zu \n", size);
    if(!testbinaryfuse8(size, 0)) { abort(); }
    printf("\n");
    if(!testbinaryfuse16(size, 0)) { abort(); }
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
