#include "fusefilter.h"
#include "xorfilter.h"
#include <assert.h>

bool testbufferedxor8() {
  printf("testing buffered xor8\n");

  xor8_t filter;
  size_t size = 10000;
  xor8_allocate(size, &filter);
  // we need some set of values
  uint64_t *big_set = (uint64_t *)malloc(sizeof(uint64_t) * size);
  for (size_t i = 0; i < size; i++) {
    big_set[i] = i; // we use contiguous values
  }
  // we construct the filter
  xor8_buffered_populate(big_set, size, &filter);
  for (size_t i = 0; i < size; i++) {
    if (!xor8_contain(big_set[i], &filter)) {
      printf("bug!\n");
      return false;
    }
  }

  size_t random_matches = 0;
  size_t trials = 10000000; //(uint64_t)rand() << 32 + rand()
  for (size_t i = 0; i < trials; i++) {
    uint64_t random_key = ((uint64_t)rand() << 32) + rand();
    if (xor8_contain(random_key, &filter)) {
      if (random_key >= size) {
        random_matches++;
      }
    }
  }
  printf("fpp %3.10f (estimated) \n", random_matches * 1.0 / trials);
  printf("bits per entry %3.1f\n", xor8_size_in_bytes(&filter) * 8.0 / size);
  xor8_free(&filter);
  free(big_set);
  return true;
}


bool testxor8() {
  printf("testing xor8\n");

  xor8_t filter;
  size_t size = 10000;
  xor8_allocate(size, &filter);
  // we need some set of values
  uint64_t *big_set = (uint64_t *)malloc(sizeof(uint64_t) * size);
  for (size_t i = 0; i < size; i++) {
    big_set[i] = i; // we use contiguous values
  }
  // we construct the filter
  xor8_populate(big_set, size, &filter);
  for (size_t i = 0; i < size; i++) {
    if (!xor8_contain(big_set[i], &filter)) {
      printf("bug!\n");
      return false;
    }
  }

  size_t random_matches = 0;
  size_t trials = 10000000; //(uint64_t)rand() << 32 + rand()
  for (size_t i = 0; i < trials; i++) {
    uint64_t random_key = ((uint64_t)rand() << 32) + rand();
    if (xor8_contain(random_key, &filter)) {
      if (random_key >= size) {
        random_matches++;
      }
    }
  }
  printf("fpp %3.10f (estimated) \n", random_matches * 1.0 / trials);
  printf("bits per entry %3.1f\n", xor8_size_in_bytes(&filter) * 8.0 / size);
  xor8_free(&filter);
  free(big_set);
  return true;
}

bool testxor16() {
  printf("testing xor16\n");
  xor16_t filter;
  size_t size = 10000;
  xor16_allocate(size, &filter);
  // we need some set of values
  uint64_t *big_set = (uint64_t *)malloc(sizeof(uint64_t) * size);
  for (size_t i = 0; i < size; i++) {
    big_set[i] = i; // we use contiguous values
  }
  // we construct the filter
  xor16_populate(big_set, size, &filter);
  for (size_t i = 0; i < size; i++) {
    if (!xor16_contain(big_set[i], &filter)) {
      printf("bug!\n");
      return false;
    }
  }

  size_t random_matches = 0;
  size_t trials = 10000000; //(uint64_t)rand() << 32 + rand()
  for (size_t i = 0; i < trials; i++) {
    uint64_t random_key = ((uint64_t)rand() << 32) + rand();
    if (xor16_contain(random_key, &filter)) {
      if (random_key >= size) {
        random_matches++;
      }
    }
  }
  printf("fpp %3.10f (estimated) \n", random_matches * 1.0 / trials);
  printf("bits per entry %3.1f\n", xor16_size_in_bytes(&filter) * 8.0 / size);
  xor16_free(&filter);
  free(big_set);
  return true;
}


bool testbufferedxor16() {
  printf("testing buffered xor16\n");
  xor16_t filter;
  size_t size = 10000;
  xor16_allocate(size, &filter);
  // we need some set of values
  uint64_t *big_set = (uint64_t *)malloc(sizeof(uint64_t) * size);
  for (size_t i = 0; i < size; i++) {
    big_set[i] = i; // we use contiguous values
  }
  // we construct the filter
  xor16_buffered_populate(big_set, size, &filter);
  for (size_t i = 0; i < size; i++) {
    if (!xor16_contain(big_set[i], &filter)) {
      printf("bug!\n");
      return false;
    }
  }

  size_t random_matches = 0;
  size_t trials = 10000000; //(uint64_t)rand() << 32 + rand()
  for (size_t i = 0; i < trials; i++) {
    uint64_t random_key = ((uint64_t)rand() << 32) + rand();
    if (xor16_contain(random_key, &filter)) {
      if (random_key >= size) {
        random_matches++;
      }
    }
  }
  printf("fpp %3.10f (estimated) \n", random_matches * 1.0 / trials);
  printf("bits per entry %3.1f\n", xor16_size_in_bytes(&filter) * 8.0 / size);
  xor16_free(&filter);
  free(big_set);
  return true;
}

bool testfuse8() {
  printf("testing fuse8\n");

  fuse8_t filter;
  size_t size = 1000000;
  fuse8_allocate(size, &filter);
  // we need some set of values
  uint64_t *big_set = (uint64_t *)malloc(sizeof(uint64_t) * size);
  for (size_t i = 0; i < size; i++) {
    big_set[i] = i; // we use contiguous values
  }
  // we construct the filter
  fuse8_populate(big_set, size, &filter);
  for (size_t i = 0; i < size; i++) {
    if (!fuse8_contain(big_set[i], &filter)) {
      printf("bug!\n");
      return false;
    }
  }

  size_t random_matches = 0;
  size_t trials = 10000000; //(uint64_t)rand() << 32 + rand()
  for (size_t i = 0; i < trials; i++) {
    uint64_t random_key = ((uint64_t)rand() << 32) + rand();
    if (fuse8_contain(random_key, &filter)) {
      if (random_key >= size) {
        random_matches++;
      }
    }
  }
  printf("fpp %3.10f (estimated) \n", random_matches * 1.0 / trials);
  printf("bits per entry %3.1f\n", fuse8_size_in_bytes(&filter) * 8.0 / size);
  fuse8_free(&filter);
  free(big_set);
  return true;
}

int main() {
  testfuse8();
  testbufferedxor8();
  testbufferedxor16();
  testxor8();
  testxor16();
}
