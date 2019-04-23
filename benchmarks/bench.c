#include "xorfilter.h"
#include <assert.h>
#include <time.h>

bool testxor8() {
  printf("testing xor8\n");

  xor8_t filter;
  size_t size = 50 * 1000 * 1000;
  xor8_allocate(size, &filter);
  // we need some set of values
  uint64_t *big_set = (uint64_t *)malloc(sizeof(uint64_t) * size);
  for (size_t i = 0; i < size; i++) {
    big_set[i] = i; // we use contiguous values
  }
  // we construct the filter
  clock_t t; 
  t = clock(); 
  xor8_populate(big_set, size, &filter);
  t = clock() - t; 
  double time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds 
  printf("It took %f seconds to build an index over %zu values. \n", time_taken, size); 
  xor8_free(&filter);
  free(big_set);
  return true;
}

bool testbufferedxor8() {
  printf("testing buffered xor8\n");

  xor8_t filter;
  size_t size = 50 * 1000 * 1000 ;//* 1000 * 1000;
  printf("size = %zu \n",size);
  xor8_allocate(size, &filter);
  // we need some set of values
  uint64_t *big_set = (uint64_t *)malloc(sizeof(uint64_t) * size);
  for (size_t i = 0; i < size; i++) {
    big_set[i] = i; // we use contiguous values
  }
  // we construct the filter
  clock_t t; 
  t = clock(); 
  xor8_buffered_populate(big_set, size, &filter);
  t = clock() - t; 
  double time_taken = ((double)t)/CLOCKS_PER_SEC; // in seconds 
  printf("It took %f seconds to build an index over %zu values. \n", time_taken, size); 
  xor8_free(&filter);
  free(big_set);
  return true;
}


int main() {
  testbufferedxor8();
  testxor8();


}
