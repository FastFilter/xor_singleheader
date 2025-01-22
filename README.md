## Header-only Xor and Binary Fuse Filter library
[![Ubuntu 22.04 CI (GCC 11)](https://github.com/FastFilter/xor_singleheader/actions/workflows/ubuntu.yml/badge.svg)](https://github.com/FastFilter/xor_singleheader/actions/workflows/ubuntu.yml)
[![MSYS2-CI](https://github.com/FastFilter/xor_singleheader/actions/workflows/msys2.yml/badge.svg)](https://github.com/FastFilter/xor_singleheader/actions/workflows/msys2.yml)

Bloom filters are used to quickly check whether an element is part of a set.
Xor filters and binary fuse filters are faster and more concise alternative to Bloom filters.
Furthermore, unlike Bloom filters, xor and binary fuse filters are naturally compressible using standard techniques (gzip, zstd, etc.).
They are also smaller than cuckoo filters. They are used in [production systems](https://github.com/datafuselabs/databend).

* Thomas Mueller Graf, Daniel Lemire, [Binary Fuse Filters: Fast and Smaller Than Xor Filters](http://arxiv.org/abs/2201.01174), Journal of Experimental Algorithmics (to appear). DOI: 10.1145/3510449
* Thomas Mueller Graf,  Daniel Lemire, [Xor Filters: Faster and Smaller Than Bloom and Cuckoo Filters](https://arxiv.org/abs/1912.08258), Journal of Experimental Algorithmics 25 (1), 2020. DOI: 10.1145/3376122


<img src="figures/comparison.png" width="50%"/>

This is a simple C header-only library. It implements both binary fuse and xor filters.


To use the state-of-the-art binary fuse filters, simply add (for example) the `binaryfusefilter.h` file to your project.  It is made available under the business-friendly Apache license.


For a simple application built on this library, see
https://github.com/FastFilter/FilterPassword

We are assuming that your set is made of 64-bit integers. If you have a set of strings
or other data structures, you need to hash them first to a 64-bit integer. It
is not important to have a good hash function, but collisions should be unlikely
(~1/2^64). A few collisions are acceptable, but we expect that your initial set
should have no duplicated entry.

The basic version works with 8-bit word and has a false-positive probability of
1/256 (or 0.4%).

```C
uint64_t *big_set = ...
binary_fuse8_t filter;
bool is_ok = binary_fuse8_allocate(size, &filter);
if(! is_ok ) {
    // do something (you have run out of memory)
}
is_ok = binary_fuse8_populate(big_set, size, &filter);
if(! is_ok ) {
    // do something (you have run out of memory)
}
binary_fuse8_contain(big_set[0], &filter); // will be true
binary_fuse8_contain(somerandomvalue, &filter); // will be false with high probability

binary_fuse8_free(&filter);
```

We also have a 16-bit version which uses about twice the memory,
but has a far lower false-positive probability (256 times smaller):
about 0.0015%. The type is `binary_fuse16_t` and you may use it with
functions such as `binary_fuse16_allocate`, `binary_fuse16_populate`,
`binary_fuse8_contain` and `binary_fuse8_free`.

For serialization, there is a choice between an unpacked and a packed format.

The unpacked format is roughly of the same size as in-core data, but uses most
efficient memory copy operations.

The packed format avoids storing zero bytes and relies on a bitset to locate them, so it
should be expected to be somewhat slower. The packed format might be smaller or larger.
It might be beneficial when using 16-bit binary fuse filters for users who need to preserve
every bytes, and who do not care about the computational overhead.
When in doubt, prefer the regular (unpacked) format.

The two formats use slightly different APIs.

You may serialize and deserialize in unpacked format as follows:

```C
  size_t buffer_size = binary_fuse16_serialization_bytes(&filter);
  char *buffer = (char*)malloc(buffer_size);
  binary_fuse16_serialize(&filter, buffer);
  binary_fuse16_free(&filter);
  binary_fuse16_deserialize(&filter, buffer);
  free(buffer);
```

This should be the default.

To serialize and deserialize in packed format, use the `_pack_bytes()`,
`_pack()` and `_unpack()` functions. The latter two have an additional `size_t`
argument for the buffer length. `_pack()` can be used with a buffer of arbitrary
size, it returns the used space if serialization fit into the buffer or 0
otherwise. Note that the packed format will be slower and may not save space
although it is likely smaller on disk when using the 16-bit binary fuse filters.

For example:

```C
  size_t buffer_size = binary_fuse16_pack_bytes(&filter);
  char *buffer = (char*)malloc(buffer_size);
  if (binary_fuse16_pack(&filter, buffer, buffer_size) != buffer_size) {
    printf("pack failed\n");
    free(buffer);
    return;
  }
  binary_fuse16_free(&filter);
  if (! binary_fuse16_unpack(&filter, buffer, buffer_size)) {
    printf("unpack failed\n");
  }
  free(buffer);
```

Either serialization does not handle endianess changes: it is expected that you
serialize and deserialize with equal byte order.

## C++ wrapper

If you want a C++ version, we recommend [binfuse](https://github.com/oschonrock/binfuse) by Oliver Schönrock.


You can also roll your own:

```C++
#include "binaryfusefilter.h"

class BinaryFuse {
public:
    explicit BinaryFuse(const size_t size) {
        if (!binary_fuse8_allocate(size, &filter)) {
            throw ::std::runtime_error("Allocation failed.");
        }
    }
    ~BinaryFuse() {
        binary_fuse8_free(&filter);
    }

    bool AddAll(uint64_t* data, const size_t start, const size_t end) {
        return binary_fuse8_populate(data + start, end - start, &filter);
    }
    inline bool Contain(uint64_t &item) const {
        return binary_fuse8_contain(item, &filter);
    }
    inline size_t SizeInBytes() const {
        return binary_fuse8_size_in_bytes(&filter);
    }
    BinaryFuse(BinaryFuse && o) : filter(o.filter)  {
        o.filter.Fingerprints = nullptr; // we take ownership for the data
    }
    binary_fuse8_t filter;

private:
    BinaryFuse(const BinaryFuse & o) = delete;
};
```


## Memory requirement

The construction of a binary fuse filter is fast but it needs a fair amount of temporary memory: plan for about 24 bytes of memory per set entry. It is possible to construct a binary fuse filter with almost no temporary memory, but the construction is then somewhat slower.

## Persistent usage

The data structure of a `binary_fuse8_t` instance quite simple. Thus you can easily save it to disk or memory-map it. E.g., we have

```C
typedef struct binary_fuse8_s {
  uint64_t Seed;
  uint32_t SegmentLength;
  uint32_t SegmentLengthMask;
  uint32_t SegmentCount;
  uint32_t SegmentCountLength;
  uint32_t ArrayLength;
  uint8_t *Fingerprints; // points to ArrayLength bytes
} binary_fuse8_t;
```

## Running tests and benchmarks

To run tests: `make test`.


```
$ make test
$ ./unit
./unit
testing binary fuse8
 fpp 0.00392 (estimated)
 bits per entry 9.04
 bits per entry 7.99 (theoretical lower bound)
 efficiency ratio 1.131
....
```

To run construction benchmarks:
```
$ make bench
$ ./bench

❯ ./bench
testing binary fuse8 size = 10000000
It took 0.358196 seconds to build an index over 10000000 values.
It took 0.355775 seconds to build an index over 10000000 values.
It took 0.367437 seconds to build an index over 10000000 values.
It took 0.358578 seconds to build an index over 10000000 values.
It took 0.358220 seconds to build an index over 10000000 values.
...
```

## Implementations of xor and binary fuse filters in other programmming languages

* [Go](https://github.com/FastFilter/xorfilter)
* [Erlang](https://github.com/mpope9/exor_filter)
* Rust: [1](https://github.com/bnclabs/xorfilter), [2](https://github.com/codri/xorfilter-rs), [3](https://github.com/Polochon-street/rustxorfilter)
* [Zig](https://github.com/hexops/fastfilter)
* [C++](https://github.com/FastFilter/fastfilter_cpp)
* [Java](https://github.com/FastFilter/fastfilter_java)
* [Python](https://github.com/GreyDireWolf/pyxorfilter)
* [C99](https://github.com/skeeto/xf8)
* [Julia](https://github.com/JokingHero/FastFilter.jl)
* [C#](https://github.com/jonmat/FastIndex)
