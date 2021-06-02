#include "binaryfusefilter.h"
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
  double fpp = random_matches * 1.0 / trials;
  printf(" fpp %3.5f (estimated) \n", fpp);
  double bpe = xor8_size_in_bytes(&filter) * 8.0 / size;
  printf(" bits per entry %3.2f\n", bpe);
  printf(" bits per entry %3.2f (theoretical lower bound)\n", - log(fpp)/log(2));
  printf(" efficiency ratio %3.3f \n", bpe /(- log(fpp)/log(2)));

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
  double fpp = random_matches * 1.0 / trials;
  printf(" fpp %3.5f (estimated) \n", fpp);
  double bpe = xor8_size_in_bytes(&filter) * 8.0 / size;
  printf(" bits per entry %3.2f\n", bpe);
  printf(" bits per entry %3.2f (theoretical lower bound)\n", - log(fpp)/log(2));
  printf(" efficiency ratio %3.3f \n", bpe /(- log(fpp)/log(2)));
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
  double fpp = random_matches * 1.0 / trials;
  printf(" fpp %3.5f (estimated) \n", fpp);
  double bpe = xor16_size_in_bytes(&filter) * 8.0 / size;
  printf(" bits per entry %3.2f\n", bpe);
  printf(" bits per entry %3.2f (theoretical lower bound)\n", - log(fpp)/log(2));
  printf(" efficiency ratio %3.3f \n", bpe /(- log(fpp)/log(2)));
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
  double fpp = random_matches * 1.0 / trials;
  printf(" fpp %3.5f (estimated) \n", fpp);
  double bpe = xor16_size_in_bytes(&filter) * 8.0 / size;
  printf(" bits per entry %3.2f\n", bpe);
  printf(" bits per entry %3.2f (theoretical lower bound)\n", - log(fpp)/log(2));
  printf(" efficiency ratio %3.3f \n", bpe /(- log(fpp)/log(2)));
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
  double fpp = random_matches * 1.0 / trials;
  printf(" fpp %3.5f (estimated) \n", fpp);
  double bpe = fuse8_size_in_bytes(&filter) * 8.0 / size;
  printf(" bits per entry %3.2f\n", bpe);
  printf(" bits per entry %3.2f (theoretical lower bound)\n", - log(fpp)/log(2));
  printf(" efficiency ratio %3.3f \n", bpe /(- log(fpp)/log(2)));
  fuse8_free(&filter);
  free(big_set);
  return true;
}

bool testbinaryfuse8() {
  printf("testing binary fuse8\n");

  binary_fuse8_t filter;
  size_t size = 1000000;
  binary_fuse8_allocate(size, &filter);
  // we need some set of values
  uint64_t *big_set = (uint64_t *)malloc(sizeof(uint64_t) * size);
  for (size_t i = 0; i < size; i++) {
    big_set[i] = i; // we use contiguous values
  }
  // we construct the filter
  binary_fuse8_populate(big_set, size, &filter);
  for (size_t i = 0; i < size; i++) {
    if (!binary_fuse8_contain(big_set[i], &filter)) {
      printf("bug!\n");
      return false;
    }
  }

  size_t random_matches = 0;
  size_t trials = 10000000; //(uint64_t)rand() << 32 + rand()
  for (size_t i = 0; i < trials; i++) {
    uint64_t random_key = ((uint64_t)rand() << 32) + rand();
    if (binary_fuse8_contain(random_key, &filter)) {
      if (random_key >= size) {
        random_matches++;
      }
    }
  }
  double fpp = random_matches * 1.0 / trials;
  printf(" fpp %3.5f (estimated) \n", fpp);
  double bpe = binary_fuse8_size_in_bytes(&filter) * 8.0 / size;
  printf(" bits per entry %3.2f\n", bpe);
  printf(" bits per entry %3.2f (theoretical lower bound)\n", - log(fpp)/log(2));
  printf(" efficiency ratio %3.3f \n", bpe /(- log(fpp)/log(2)));
  binary_fuse8_free(&filter);
  free(big_set);
  return true;
}

int main() {
  testbinaryfuse8();
  printf("\n");
  testfuse8();
  printf("\n");
  testbufferedxor8();
  printf("\n");
  testbufferedxor16();
  printf("\n");
  testxor8();
  printf("\n");
  testxor16();
  printf("\n");
}
