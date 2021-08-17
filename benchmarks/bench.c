#include "binaryfusefilter.h"
#include "xorfilter.h"
#include <assert.h>
#include <time.h>

bool testxor8(size_t size) {
  printf("testing xor8 ");
  printf("size = %zu \n", size);

  xor8_t filter;

  xor8_allocate(size, &filter);
  // we need some set of values
  uint64_t *big_set = (uint64_t *)malloc(sizeof(uint64_t) * size);
  for (size_t i = 0; i < size; i++) {
    big_set[i] = i; // we use contiguous values
  }
  // we construct the filter
  xor8_populate(big_set, size, &filter); // warm the cache
  for (size_t times = 0; times < 5; times++) {
    clock_t t;
    t = clock();
    xor8_populate(big_set, size, &filter);
    t = clock() - t;
    double time_taken = ((double)t) / CLOCKS_PER_SEC; // in seconds
    printf("It took %f seconds to build an index over %zu values. \n",
           time_taken, size);
  }
  xor8_free(&filter);
  free(big_set);
  return true;
}

bool testbufferedxor8(size_t size) {
  printf("testing buffered xor8 ");
  printf("size = %zu \n", size);

  xor8_t filter;
  xor8_allocate(size, &filter);
  // we need some set of values
  uint64_t *big_set = (uint64_t *)malloc(sizeof(uint64_t) * size);
  for (size_t i = 0; i < size; i++) {
    big_set[i] = i; // we use contiguous values
  }
  // we construct the filter
  xor8_buffered_populate(big_set, size, &filter); // warm the cache
  for (size_t times = 0; times < 5; times++) {
    clock_t t;
    t = clock();
    xor8_buffered_populate(big_set, size, &filter);
    t = clock() - t;
    double time_taken = ((double)t) / CLOCKS_PER_SEC; // in seconds
    printf("It took %f seconds to build an index over %zu values. \n",
           time_taken, size);
  }
  xor8_free(&filter);
  free(big_set);
  return true;
}

bool testxor16(size_t size) {
  printf("testing xor16 ");
  printf("size = %zu \n", size);

  xor16_t filter;
  xor16_allocate(size, &filter);
  // we need some set of values
  uint64_t *big_set = (uint64_t *)malloc(sizeof(uint64_t) * size);
  for (size_t i = 0; i < size; i++) {
    big_set[i] = i; // we use contiguous values
  }
  // we construct the filter
  xor16_populate(big_set, size, &filter); // warm the cache
  for (size_t times = 0; times < 5; times++) {
    clock_t t;
    t = clock();
    xor16_populate(big_set, size, &filter);
    t = clock() - t;
    double time_taken = ((double)t) / CLOCKS_PER_SEC; // in seconds
    printf("It took %f seconds to build an index over %zu values. \n",
           time_taken, size);
  }
  xor16_free(&filter);
  free(big_set);
  return true;
}

bool testbufferedxor16(size_t size) {
  printf("testing buffered xor16 ");
  printf("size = %zu \n", size);

  xor16_t filter;
  xor16_allocate(size, &filter);
  // we need some set of values
  uint64_t *big_set = (uint64_t *)malloc(sizeof(uint64_t) * size);
  for (size_t i = 0; i < size; i++) {
    big_set[i] = i; // we use contiguous values
  }
  // we construct the filter
  xor16_buffered_populate(big_set, size, &filter); // warm the cache
  for (size_t times = 0; times < 5; times++) {
    clock_t t;
    t = clock();
    xor16_buffered_populate(big_set, size, &filter);
    t = clock() - t;
    double time_taken = ((double)t) / CLOCKS_PER_SEC; // in seconds
    printf("It took %f seconds to build an index over %zu values. \n",
           time_taken, size);
  }
  xor16_free(&filter);
  free(big_set);
  return true;
}

bool testbinaryfuse8(size_t size) {
  printf("testing binary fuse8 ");
  printf("size = %zu \n", size);

  binary_fuse8_t filter;

  binary_fuse8_allocate(size, &filter);
  // we need some set of values
  uint64_t *big_set = (uint64_t *)malloc(sizeof(uint64_t) * size);
  for (size_t i = 0; i < size; i++) {
    big_set[i] = i; // we use contiguous values
  }
  // we construct the filter
  binary_fuse8_populate(big_set, size, &filter); // warm the cache
  for (size_t times = 0; times < 5; times++) {
    clock_t t;
    t = clock();
    binary_fuse8_populate(big_set, size, &filter);
    t = clock() - t;
    double time_taken = ((double)t) / CLOCKS_PER_SEC; // in seconds
    printf("It took %f seconds to build an index over %zu values. \n",
           time_taken, size);
  }
  binary_fuse8_free(&filter);
  free(big_set);
  return true;
}

bool testbinaryfuse16(size_t size) {
  printf("testing binary fuse16 ");
  printf("size = %zu \n", size);

  binary_fuse16_t filter;

  binary_fuse16_allocate(size, &filter);
  // we need some set of values
  uint64_t *big_set = (uint64_t *)malloc(sizeof(uint64_t) * size);
  for (size_t i = 0; i < size; i++) {
    big_set[i] = i; // we use contiguous values
  }
  // we construct the filter
  binary_fuse16_populate(big_set, size, &filter); // warm the cache
  for (size_t times = 0; times < 5; times++) {
    clock_t t;
    t = clock();
    binary_fuse16_populate(big_set, size, &filter);
    t = clock() - t;
    double time_taken = ((double)t) / CLOCKS_PER_SEC; // in seconds
    printf("It took %f seconds to build an index over %zu values. \n",
           time_taken, size);
  }
  binary_fuse16_free(&filter);
  free(big_set);
  return true;
}

int main() {
  for (size_t s = 10000000; s <= 10000000; s *= 10) {
    testbinaryfuse8(s);
    testbufferedxor8(s);
    testxor8(s);
    testbinaryfuse16(s);
    testbufferedxor16(s);
    testxor16(s);

    printf("\n");
  }
}
