#include "binaryfusefilter.h"
#include "xorfilter.h"
#include <assert.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#define N 1000000UL
#define Q N

static double time_seconds() {
  return (double)clock() / (double)CLOCKS_PER_SEC;
}

static void run_binaryfuse8() {
  printf("\nRunning binary_fuse8 query benchmark\n");
  binary_fuse8_t filter;
  if (!binary_fuse8_allocate((uint32_t)N, &filter)) {
    fprintf(stderr, "binary_fuse8_allocate failed\n");
    return;
  }
  uint64_t *keys = (uint64_t *)malloc(sizeof(uint64_t) * N);
  for (size_t i = 0; i < N; i++) keys[i] = (uint64_t)i * 2ULL; // even numbers
  if (!binary_fuse8_populate(keys, (uint32_t)N, &filter)) {
    fprintf(stderr, "binary_fuse8_populate failed\n");
    binary_fuse8_free(&filter);
    free(keys);
    return;
  }

  // warm up
  for (size_t i = 0; i < 1000; i++) binary_fuse8_contain(keys[i], &filter);

  size_t found = 0;
  double t0 = time_seconds();
  for (size_t i = 0; i < Q; i++) {
    if (binary_fuse8_contain((uint64_t)i, &filter)) found++;
  }
  double t1 = time_seconds();
  double secs = t1 - t0;
    double qps = (double)Q / secs;
    double ns_per_q = (secs * 1e9) / (double)Q;
    printf("binary_fuse8: %zu queries in %f s => %f q/s, %f ns/q, found=%zu\n",
      (size_t)Q, secs, qps, ns_per_q, found);

  binary_fuse8_free(&filter);
  free(keys);
}

static void run_xor8() {
  printf("\nRunning xor8 query benchmark\n");
  xor8_t filter;
  if (!xor8_allocate((uint32_t)N, &filter)) {
    fprintf(stderr, "xor8_allocate failed\n");
    return;
  }
  uint64_t *keys = (uint64_t *)malloc(sizeof(uint64_t) * N);
  for (size_t i = 0; i < N; i++) keys[i] = (uint64_t)i * 2ULL; // even numbers
  if (!xor8_populate(keys, (uint32_t)N, &filter)) {
    fprintf(stderr, "xor8_populate failed\n");
    xor8_free(&filter);
    free(keys);
    return;
  }

  for (size_t i = 0; i < 1000; i++) xor8_contain(keys[i], &filter);

  size_t found = 0;
  double t0 = time_seconds();
  for (size_t i = 0; i < Q; i++) {
    if (xor8_contain((uint64_t)i, &filter)) found++;
  }
  double t1 = time_seconds();
  double secs = t1 - t0;
  {
    double qps = (double)Q / secs;
    double ns_per_q = (secs * 1e9) / (double)Q;
    printf("xor8: %zu queries in %f s => %f q/s, %f ns/q, found=%zu\n",
           (size_t)Q, secs, qps, ns_per_q, found);
  }

  xor8_free(&filter);
  free(keys);
}

static void run_binaryfuse16() {
  printf("\nRunning binary_fuse16 query benchmark\n");
  binary_fuse16_t filter;
  if (!binary_fuse16_allocate((uint32_t)N, &filter)) {
    fprintf(stderr, "binary_fuse16_allocate failed\n");
    return;
  }
  uint64_t *keys = (uint64_t *)malloc(sizeof(uint64_t) * N);
  for (size_t i = 0; i < N; i++) keys[i] = (uint64_t)i * 2ULL; // even numbers
  if (!binary_fuse16_populate(keys, (uint32_t)N, &filter)) {
    fprintf(stderr, "binary_fuse16_populate failed\n");
    binary_fuse16_free(&filter);
    free(keys);
    return;
  }

  for (size_t i = 0; i < 1000; i++) binary_fuse16_contain(keys[i], &filter);

  size_t found = 0;
  double t0 = time_seconds();
  for (size_t i = 0; i < Q; i++) {
    if (binary_fuse16_contain((uint64_t)i, &filter)) found++;
  }
  double t1 = time_seconds();
  double secs = t1 - t0;
  {
    double qps = (double)Q / secs;
    double ns_per_q = (secs * 1e9) / (double)Q;
    printf("binary_fuse16: %zu queries in %f s => %f q/s, %f ns/q, found=%zu\n",
           (size_t)Q, secs, qps, ns_per_q, found);
  }

  binary_fuse16_free(&filter);
  free(keys);
}

static void run_xor16() {
  printf("\nRunning xor16 query benchmark\n");
  xor16_t filter;
  if (!xor16_allocate((uint32_t)N, &filter)) {
    fprintf(stderr, "xor16_allocate failed\n");
    return;
  }
  uint64_t *keys = (uint64_t *)malloc(sizeof(uint64_t) * N);
  for (size_t i = 0; i < N; i++) keys[i] = (uint64_t)i * 2ULL; // even numbers
  if (!xor16_populate(keys, (uint32_t)N, &filter)) {
    fprintf(stderr, "xor16_populate failed\n");
    xor16_free(&filter);
    free(keys);
    return;
  }

  for (size_t i = 0; i < 1000; i++) xor16_contain(keys[i], &filter);

  size_t found = 0;
  double t0 = time_seconds();
  for (size_t i = 0; i < Q; i++) {
    if (xor16_contain((uint64_t)i, &filter)) found++;
  }
  double t1 = time_seconds();
  double secs = t1 - t0;
  {
    double qps = (double)Q / secs;
    double ns_per_q = (secs * 1e9) / (double)Q;
    printf("xor16: %zu queries in %f s => %f q/s, %f ns/q, found=%zu\n",
           (size_t)Q, secs, qps, ns_per_q, found);
  }

  xor16_free(&filter);
  free(keys);
}

int main() {
  run_binaryfuse8();
  run_xor8();
  run_binaryfuse16();
  run_xor16();
  return 0;
}
