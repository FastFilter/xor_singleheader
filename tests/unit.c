#include "binaryfusefilter.h"
#include "xorfilter.h"
#include <assert.h>

bool gen_xor8_contain(uint64_t key, const void* filter) { return xor8_contain(key, filter); }
bool gen_xor16_contain(uint64_t key, const void* filter) { return xor16_contain(key, filter); }
bool gen_binary_fuse8_contain(uint64_t key, const void* filter) { return binary_fuse8_contain(key, filter); }
bool gen_binary_fuse16_contain(uint64_t key, const void* filter) { return binary_fuse16_contain(key, filter); }

size_t gen_xor8_size_in_bytes(const void* filter) { return xor8_size_in_bytes(filter); }
size_t gen_xor16_size_in_bytes(const void* filter) { return xor16_size_in_bytes(filter); }
size_t gen_binary_fuse8_size_in_bytes(const void* filter) { return binary_fuse8_size_in_bytes(filter); }
size_t gen_binary_fuse16_size_in_bytes(const void* filter) { return binary_fuse16_size_in_bytes(filter); }

typedef bool (*contain_fpt)(uint64_t key, const void *filter);
typedef size_t (*size_in_bytes_fpt)(const void *filter);

void report(size_t size, void* filter, contain_fpt contain, size_in_bytes_fpt size_in_bytes) {
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
}

bool testbufferedxor8(size_t size) {
  printf("testing buffered xor8\n");

  xor8_t filter = {0}; // zero initialisation silences unitialized warning
  xor8_allocate((uint32_t)size, &filter);
  // we need some set of values
  uint64_t *big_set = (uint64_t *)malloc(sizeof(uint64_t) * size);
  for (size_t i = 0; i < size; i++) {
    big_set[i] = i; // we use contiguous values
  }
  // we construct the filter
  if(!xor8_buffered_populate(big_set, (uint32_t)size, &filter)) { return false; }
  for (size_t i = 0; i < size; i++) {
    if (!xor8_contain(big_set[i], &filter)) {
      printf("bug!\n");
      return false;
    }
  }

  size_t buffer_size = xor8_serialization_bytes(&filter);
  char *buffer = (char*)malloc(buffer_size);
  xor8_serialize(&filter, buffer);
  xor8_free(&filter);
  xor8_deserialize(&filter, buffer);
  free(buffer);
  for (size_t i = 0; i < size; i++) {
    if (!xor8_contain(big_set[i], &filter)) {
      printf("bug!\n");
      return false;
    }
  }
  
  report(size, &filter, gen_xor8_contain, gen_xor8_size_in_bytes);
  
  xor8_free(&filter);
  free(big_set);
  return true;
}


bool testxor8(size_t size) {
  printf("testing xor8\n");

  xor8_t filter = {0}; // zero initialisation silences unitialized warning
  xor8_allocate((uint32_t)size, &filter);
  // we need some set of values
  uint64_t *big_set = (uint64_t *)malloc(sizeof(uint64_t) * size);
  for (size_t i = 0; i < size; i++) {
    big_set[i] = i; // we use contiguous values
  }
  // we construct the filter
  if(!xor8_populate(big_set, (uint32_t)size, &filter)) { return false; }
  for (size_t i = 0; i < size; i++) {
    if (!xor8_contain(big_set[i], &filter)) {
      printf("bug!\n");
      return false;
    }
  }

  size_t buffer_size = xor8_serialization_bytes(&filter);
  char *buffer = (char*)malloc(buffer_size);
  xor8_serialize(&filter, buffer);
  xor8_free(&filter);
  xor8_deserialize(&filter, buffer);
  free(buffer);
  for (size_t i = 0; i < size; i++) {
    if (!xor8_contain(big_set[i], &filter)) {
      printf("bug!\n");
      return false;
    }
  }

  report(size, &filter, gen_xor8_contain, gen_xor8_size_in_bytes);
  
  xor8_free(&filter);
  free(big_set);
  return true;
}

bool testxor16(size_t size) {
  printf("testing xor16\n");
  xor16_t filter = {0}; // zero initialisation silences unitialized warning
  xor16_allocate((uint32_t)size, &filter);
  // we need some set of values
  uint64_t *big_set = (uint64_t *)malloc(sizeof(uint64_t) * size);
  for (size_t i = 0; i < size; i++) {
    big_set[i] = i; // we use contiguous values
  }
  // we construct the filter
  if(!xor16_populate(big_set, (uint32_t)size, &filter)) { return false; }
  for (size_t i = 0; i < size; i++) {
    if (!xor16_contain(big_set[i], &filter)) {
      printf("bug!\n");
      return false;
    }
  }

  size_t buffer_size = xor16_serialization_bytes(&filter);
  char *buffer = (char*)malloc(buffer_size);
  xor16_serialize(&filter, buffer);
  xor16_free(&filter);
  xor16_deserialize(&filter, buffer);
  free(buffer);
  for (size_t i = 0; i < size; i++) {
    if (!xor16_contain(big_set[i], &filter)) {
      printf("bug!\n");
      return false;
    }
  }

  report(size, &filter, gen_xor16_contain, gen_xor16_size_in_bytes);
  
  xor16_free(&filter);
  free(big_set);
  return true;
}


bool testbufferedxor16(size_t size) {
  printf("testing buffered xor16\n");
  xor16_t filter = {0}; // zero initialisation silences unitialized warning
  xor16_allocate((uint32_t)size, &filter);
  // we need some set of values
  uint64_t *big_set = (uint64_t *)malloc(sizeof(uint64_t) * size);
  for (size_t i = 0; i < size; i++) {
    big_set[i] = i; // we use contiguous values
  }
  // we construct the filter
  if(!xor16_buffered_populate(big_set, (uint32_t)size, &filter)) { return false; }
  for (size_t i = 0; i < size; i++) {
    if (!xor16_contain(big_set[i], &filter)) {
      printf("bug!\n");
      return false;
    }
  }

  size_t buffer_size = xor16_serialization_bytes(&filter);
  char *buffer = (char*)malloc(buffer_size);
  xor16_serialize(&filter, buffer);
  xor16_free(&filter);
  xor16_deserialize(&filter, buffer);
  free(buffer);
  for (size_t i = 0; i < size; i++) {
    if (!xor16_contain(big_set[i], &filter)) {
      printf("bug!\n");
      return false;
    }
  }

  report(size, &filter, gen_xor16_contain, gen_xor16_size_in_bytes);
  
  xor16_free(&filter);
  free(big_set);
  return true;
}

bool testbinaryfuse8(size_t size) {
  printf("testing binary fuse8 with size %zu\n", size);
  binary_fuse8_t filter = {0}; // zero initialisation silences unitialized warning
  binary_fuse8_allocate((uint32_t)size, &filter);
  // we need some set of values
  uint64_t *big_set = (uint64_t *)malloc(sizeof(uint64_t) * size);
  for (size_t i = 0; i < size; i++) {
    big_set[i] = i; // we use contiguous values
  }
  // we construct the filter
  if(!binary_fuse8_populate(big_set, (uint32_t)size, &filter)) { printf("failure to populate\n"); return false; }
  for (size_t i = 0; i < size; i++) {
    if (!binary_fuse8_contain(big_set[i], &filter)) {
      printf("bug!\n");
      return false;
    }
  }

  size_t buffer_size = binary_fuse8_serialization_bytes(&filter);
  char *buffer = (char*)malloc(buffer_size);
  binary_fuse8_serialize(&filter, buffer);
  binary_fuse8_free(&filter);
  binary_fuse8_deserialize(&filter, buffer);
  free(buffer);
  for (size_t i = 0; i < size; i++) {
    if (!binary_fuse8_contain(big_set[i], &filter)) {
      printf("bug!\n");
      return false;
    }
  }

  report(size, &filter, gen_binary_fuse8_contain, gen_binary_fuse8_size_in_bytes);
  
  binary_fuse8_free(&filter);
  free(big_set);
  return true;
}



bool testbinaryfuse16(size_t size) {
  printf("testing binary fuse16\n");
  binary_fuse16_t filter = {0}; // zero initialisation silences unitialized warning
  binary_fuse16_allocate((uint32_t)size, &filter);
  // we need some set of values
  uint64_t *big_set = (uint64_t *)malloc(sizeof(uint64_t) * size);
  for (size_t i = 0; i < size; i++) {
    big_set[i] = i; // we use contiguous values
  }
  // we construct the filter
  if(!binary_fuse16_populate(big_set, (uint32_t)size, &filter)) {  printf("failure to populate\n"); return false; }
  for (size_t i = 0; i < size; i++) {
    if (!binary_fuse16_contain(big_set[i], &filter)) {
      printf("bug!\n");
      return false;
    }
  }

  size_t buffer_size = binary_fuse16_serialization_bytes(&filter);
  char *buffer = (char*)malloc(buffer_size);
  binary_fuse16_serialize(&filter, buffer);
  binary_fuse16_free(&filter);
  binary_fuse16_deserialize(&filter, buffer);
  free(buffer);
  for (size_t i = 0; i < size; i++) {
    if (!binary_fuse16_contain(big_set[i], &filter)) {
      printf("bug!\n");
      return false;
    }
  }

  report(size, &filter, gen_binary_fuse16_contain, gen_binary_fuse16_size_in_bytes);
  
  binary_fuse16_free(&filter);
  free(big_set);
  return true;
}



bool testbinaryfuse8_dup(size_t size) {
  printf("testing binary fuse8 with duplicates\n");
  binary_fuse8_t filter = {0}; // zero initialisation silences unitialized warning
  binary_fuse8_allocate((uint32_t)size, &filter);
  // we need some set of values
  uint64_t *big_set = (uint64_t *)malloc(sizeof(uint64_t) * size);
  size_t repeated_size = 10;
  for (size_t i = 0; i < size - repeated_size; i++) {
    big_set[i] = i; // we use contiguous values
  }
  for (size_t i = 0; i < repeated_size; i++) {
    big_set[size - i - 1] = i; // we use contiguous values
  }
  // we construct the filter
  if(!binary_fuse8_populate(big_set, (uint32_t)size, &filter)) { return false; }
  for (size_t i = 0; i < size; i++) {
    if (!binary_fuse8_contain(big_set[i], &filter)) {
      printf("bug!\n");
      return false;
    }
  }

  report(size, &filter, gen_binary_fuse8_contain, gen_binary_fuse8_size_in_bytes);
  
  binary_fuse8_free(&filter);
  free(big_set);
  return true;
}



bool testbinaryfuse16_dup(size_t size) {
  printf("testing binary fuse16 with duplicates\n");
  binary_fuse16_t filter = {0}; // zero initialisation silences unitialized warning
  binary_fuse16_allocate((uint32_t)size, &filter);
  // we need some set of values
  uint64_t *big_set = (uint64_t *)malloc(sizeof(uint64_t) * size);
  size_t repeated_size = 10;
  for (size_t i = 0; i < size - repeated_size; i++) {
    big_set[i] = i; // we use contiguous values
  }
  for (size_t i = 0; i < repeated_size; i++) {
    big_set[size - i - 1] = i; // we use contiguous values
  }
  // we construct the filter
  if(!binary_fuse16_populate(big_set, (uint32_t)size, &filter)) { return false; }
  for (size_t i = 0; i < size; i++) {
    if (!binary_fuse16_contain(big_set[i], &filter)) {
      printf("bug!\n");
      return false;
    }
  }

  report(size, &filter, gen_binary_fuse16_contain, gen_binary_fuse16_size_in_bytes);
  
  binary_fuse16_free(&filter);
  free(big_set);
  return true;
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
  free(big_set);
}

int main() {
  failure_rate_binary_fuse16();
  for(size_t size = 1000; size <= 1000000; size *= 300) {
    printf("== size = %zu \n", size);
    if(!testbinaryfuse8(size)) { abort(); }
    printf("\n");
    if(!testbinaryfuse16(size)) { abort(); }
    printf("\n");
    if(!testbinaryfuse8_dup(size)) { abort(); }
    printf("\n");
    if(!testbinaryfuse16_dup(size)) { abort(); }
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
  if(!testbinaryfuse8(0)) { abort(); }
  if(!testbinaryfuse8(1)) { abort(); }
  if(!testbinaryfuse8(2)) { abort(); }
  if(!testbinaryfuse16(0)) { abort(); }
  if(!testbinaryfuse16(1)) { abort(); }
  if(!testbinaryfuse16(2)) { abort(); }
}
