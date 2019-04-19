## Header-only Xor Filter library


Bloom filters are used to quickly check whether an element is part of a set.
Xor filters are a faster and more concise alternative to Bloom filters.
They are also smaller than cuckoo filters.

This is a simple C header-only library for Xor filters. It implements both xor8
and x16.

Simply add the `xorfilter.h` file to your project.  It is made available under the
business-friendly Apache license.

We are assuming that your set is made of 64-bit integers. If you have strings
or other data structures, you need to hash them first to a 64-bit integer. It
is not important to have a good hash function, but collision should be unlikely
(~1/2^64).

You can use either the xor8 filter... (false-positive rate of about 0.3 %)

```C
uint64_t *big_set = ...
xor8_t filter;
xor8_allocate(size, &filter);
xor8_populate(big_set, size, &filter);
xor8_contain(big_set[0], &filter); // will be true
xor8_contain(somerandomvalue, &filter); // will be false with high probability

xor8_free(filter);
```

Or the xor16 filter (larger but more accurate)... (vanishingly small false-positive rate)

```C
uint64_t *big_set = ...
xor16_t filter;
xor16_allocate(size, &filter);
xor16_populate(big_set, size, &filter);
xor16_contain(big_set[0], &filter); // will be true
xor16_contain(somerandomvalue, &filter); // will be false with high probability

xor16_free(filter);
```

The data structure is quite simple: two 64-bit integer and an array of either 8-bit (for xor8)
or 16-bit (for xor16) integers. Thus you can easily save it to disk or memory-map it. E.g., we have

```C
typedef struct xor16_s {
  uint64_t seed;
  uint64_t blockLength;
  uint16_t
      *fingerprints; // points to 3*blockLength values
} xor16_t;
```

To run tests: `make test`.


```
$ make test
./unit
testing xor16
fpp 0.0000154000 (estimated)
bits per entry 19.7
testing xor8
fpp 0.0039015000 (estimated)
bits per entry 9.9


