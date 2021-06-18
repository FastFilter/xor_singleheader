all: unit bench

unit : tests/unit.c include/xorfilter.h include/binaryfusefilter.h
	cc -std=c99 -O3 -o unit tests/unit.c -Iinclude -Wall -Wextra -Wshadow  -Wcast-qual

bench : benchmarks/bench.c include/xorfilter.h include/binaryfusefilter.h
	cc -std=c99 -O3 -o bench benchmarks/bench.c -Iinclude -Wall -Wextra -Wshadow  -Wcast-qual

test: unit
	./unit

clean: 
	rm -f unit bench
