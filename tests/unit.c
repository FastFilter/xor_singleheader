#include "binaryfusefilter.h"
#include "xorfilter.h"
#include <assert.h>

// generic proxy for filter, important that this is a struct, not void
// as § 6.2.5..28: "All pointers to structure types shall have the
// same representation and alignment requirements as each other"
typedef struct { int dummy_; } gen_filter; 

typedef bool (*allocate_fpt)(uint32_t size, gen_filter *filter);
typedef void (*free_fpt)(gen_filter *filter);
typedef size_t (*size_in_bytes_fpt)(const gen_filter *filter);
typedef size_t (*serialization_bytes_fpt)(gen_filter *filter);
typedef void (*serialize_fpt)(gen_filter *filter, char *buffer);
typedef bool (*deserialize_fpt)(gen_filter *filter, const char *buffer);
typedef bool (*populate_fpt)(uint64_t *keys, uint32_t size, gen_filter *filter);
typedef bool (*contain_fpt)(uint64_t key, const gen_filter *filter);

typedef void (*gfp)(void); // generic function pointer

// generic test runner
bool test(size_t size, size_t repeated_size, void *filter,
          gfp allocate,
          gfp free_filter,
          gfp size_in_bytes,
          gfp serialization_bytes,
          gfp serialize,
          gfp deserialize,
          gfp populate,
          gfp contain) {
  ((allocate_fpt)allocate)((uint32_t)size, filter);
  // we need some set of values
  uint64_t *big_set = (uint64_t *)malloc(sizeof(uint64_t) * size);
  for (size_t i = 0; i < size - repeated_size; i++) {
    big_set[i] = i; // we use contiguous values
  }
  for (size_t i = 0; i < repeated_size; i++) {
    big_set[size - i - 1] = i; // we use contiguous values
  }
  // we construct the filter
  if(!((populate_fpt)populate)(big_set, (uint32_t)size, filter)) { return false; }
  for (size_t i = 0; i < size; i++) {
    if (!((contain_fpt)contain)(big_set[i], filter)) {
      printf("bug!\n");
      return false;
    }
  }

  size_t buffer_size = ((serialization_bytes_fpt)serialization_bytes)(filter);
  char *buffer = (char*)malloc(buffer_size);
  ((serialize_fpt)serialize)(filter, buffer);
  ((free_fpt)free_filter)(filter);
  ((deserialize_fpt)deserialize)(filter, buffer);
  free(buffer);
  for (size_t i = 0; i < size; i++) {
    if (!((contain_fpt)contain)(big_set[i], filter)) {
      printf("bug!\n");
      return false;
    }
  }
  
  size_t random_matches = 0;
  size_t trials = 10000000;
  for (size_t i = 0; i < trials; i++) {
    uint64_t random_key = ((uint64_t)rand() << 32U) + (uint64_t)rand();
    if (((contain_fpt)contain)(random_key, filter)) {
      if (random_key >= size) {
        random_matches++;
      }
    }
  }
  double fpp = (double)random_matches * 1.0 / (double)trials;
  printf(" fpp %3.5f (estimated) \n", fpp);
  double bpe = (double)((size_in_bytes_fpt)size_in_bytes)(filter) * 8.0 / (double)size;
  printf(" bits per entry %3.2f\n", bpe);
  printf(" bits per entry %3.2f (theoretical lower bound)\n", - log(fpp)/log(2));
  printf(" efficiency ratio %3.3f \n", bpe /(- log(fpp)/log(2)));
  ((free_fpt)free_filter)(filter);
  free(big_set);
  return true;
}

bool testbufferedxor8(size_t size) {
  printf("testing buffered xor8\n");
  xor8_t filter;
  return test(size, 0, &filter,
              (gfp)xor8_allocate,
              (gfp)xor8_free,
              (gfp)xor8_size_in_bytes,
              (gfp)xor8_serialization_bytes,
              (gfp)xor8_serialize,
              (gfp)xor8_deserialize,
              (gfp)xor8_buffered_populate,
              (gfp)xor8_contain);
}


bool testxor8(size_t size) {
  printf("testing xor8\n");
  xor8_t filter;
  return test(size, 0, &filter,
              (gfp)xor8_allocate,
              (gfp)xor8_free,
              (gfp)xor8_size_in_bytes,
              (gfp)xor8_serialization_bytes,
              (gfp)xor8_serialize,
              (gfp)xor8_deserialize,
              (gfp)xor8_populate,
              (gfp)xor8_contain);
}

bool testxor16(size_t size) {
  printf("testing xor16\n");
  xor16_t filter;
  return test(size, 0, &filter,
              (gfp)xor16_allocate,
              (gfp)xor16_free,
              (gfp)xor16_size_in_bytes,
              (gfp)xor16_serialization_bytes,
              (gfp)xor16_serialize,
              (gfp)xor16_deserialize,
              (gfp)xor16_populate,
              (gfp)xor16_contain);
}



bool testbufferedxor16(size_t size) {
  printf("testing buffered xor16\n");
  xor16_t filter;
  return test(size, 0, &filter,
              (gfp)xor16_allocate,
              (gfp)xor16_free,
              (gfp)xor16_size_in_bytes,
              (gfp)xor16_serialization_bytes,
              (gfp)xor16_serialize,
              (gfp)xor16_deserialize,
              (gfp)xor16_buffered_populate,
              (gfp)xor16_contain);
}

bool testbinaryfuse8(size_t size, size_t repeated_size) {
  printf("testing binary fuse8 with size %zu and %zu duplicates\n", size, repeated_size);
  binary_fuse8_t filter;
  return test(size, repeated_size, &filter,
              (gfp)binary_fuse8_allocate,
              (gfp)binary_fuse8_free,
              (gfp)binary_fuse8_size_in_bytes,
              (gfp)binary_fuse8_serialization_bytes,
              (gfp)binary_fuse8_serialize,
              (gfp)binary_fuse8_deserialize,
              (gfp)binary_fuse8_populate,
              (gfp)binary_fuse8_contain);
}



bool testbinaryfuse16(size_t size, size_t repeated_size) {
  printf("testing binary fuse16 with size %zu and %zu duplicates\n", size, repeated_size);
  binary_fuse16_t filter;
  return test(size, repeated_size, &filter,
              (gfp)binary_fuse16_allocate,
              (gfp)binary_fuse16_free,
              (gfp)binary_fuse16_size_in_bytes,
              (gfp)binary_fuse16_serialization_bytes,
              (gfp)binary_fuse16_serialize,
              (gfp)binary_fuse16_deserialize,
              (gfp)binary_fuse16_populate,
              (gfp)binary_fuse16_contain);
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
