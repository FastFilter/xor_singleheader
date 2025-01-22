#include "binaryfusefilter.h"
#include "xorfilter.h"
#include <stdlib.h>
#include <iso646.h>

typedef struct {
  size_t standard;
  size_t pack;
} sizes;

sizes fuse16(size_t n) {
  binary_fuse16_t filter = {0};
  if (! binary_fuse16_allocate(n, &filter)) {
    printf("allocation failed\n");
    return (sizes) {0, 0};
  }
  uint64_t* big_set = malloc(n * sizeof(uint64_t));
  for(size_t i = 0; i < n; i++) {
    big_set[i] = i;
  }
  bool is_ok = binary_fuse16_populate(big_set, n, &filter);
  if(! is_ok ) {
    printf("populating failed\n");
  }
  free(big_set);
  sizes s = {
    .standard = binary_fuse16_serialization_bytes(&filter),
    .pack = binary_fuse16_pack_bytes(&filter)
  };
  binary_fuse16_free(&filter);
  return s;
}

sizes fuse8(size_t n) {
  binary_fuse8_t filter = {0};
  if (! binary_fuse8_allocate(n, &filter)) {
    printf("allocation failed\n");
    return (sizes) {0, 0};
  }
  uint64_t* big_set = malloc(n * sizeof(uint64_t));
  for(size_t i = 0; i < n; i++) {
    big_set[i] = i;
  }
  bool is_ok = binary_fuse8_populate(big_set, n, &filter);
  if(! is_ok ) {
    printf("populating failed\n");
  }
  free(big_set);
  sizes s = {
    .standard = binary_fuse8_serialization_bytes(&filter),
    .pack = binary_fuse8_pack_bytes(&filter)
  };
  binary_fuse8_free(&filter);
  return s;
}

sizes xor16(size_t n) {
  xor16_t filter = {0};
  if (! xor16_allocate(n, &filter)) {
    printf("allocation failed\n");
    return (sizes) {0, 0};
  }
  uint64_t* big_set = malloc(n * sizeof(uint64_t));
  for(size_t i = 0; i < n; i++) {
    big_set[i] = i;
  }
  bool is_ok = xor16_populate(big_set, n, &filter);
  if(! is_ok ) {
    printf("populating failed\n");
  }
  free(big_set);
  sizes s = {
    .standard = xor16_serialization_bytes(&filter),
    .pack = xor16_pack_bytes(&filter)
  };
  xor16_free(&filter);
  return s;
}

sizes xor8(size_t n) {
  xor8_t filter = {0};
  if (! xor8_allocate(n, &filter)) {
    printf("allocation failed\n");
    return (sizes) {0, 0};
  }
  uint64_t* big_set = malloc(n * sizeof(uint64_t));
  for(size_t i = 0; i < n; i++) {
    big_set[i] = i;
  }
  bool is_ok = xor8_populate(big_set, n, &filter);
  if(! is_ok ) {
    printf("populating failed\n");
  }
  free(big_set);
  sizes s = {
    .standard = xor8_serialization_bytes(&filter),
    .pack = xor8_pack_bytes(&filter)
  };
  xor8_free(&filter);

  return s;
}

int main() {
    for (size_t n = 10; n <= 10000000; n *= 2) {
        printf("%-10zu ", n);  // Align number to 10 characters wide
        sizes f16 = fuse16(n);
        sizes f8 = fuse8(n);
        sizes x16 = xor16(n);
        sizes x8 = xor8(n);
        
        printf("fuse16: %5.2f %5.2f   ", (double)f16.standard * 8.0 / n, (double)f16.pack * 8.0 / n);
        printf("fuse8: %5.2f %5.2f   ", (double)f8.standard  * 8.0 / n, (double)f8.pack  * 8.0 / n);
        printf("xor16: %5.2f %5.2f   ", (double)x16.standard  * 8.0 / n, (double)x16.pack  * 8.0 / n);
        printf("xor8: %5.2f %5.2f   ", (double)x8.standard  * 8.0 / n, (double)x8.pack  * 8.0 / n);
        printf("\n");
    }
    return EXIT_SUCCESS;
}
