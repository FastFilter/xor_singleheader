all: unit bench

unit : tests/unit.c include/xorfilter.h include/binaryfusefilter.h
	cc -std=c99 -O3 -o unit tests/unit.c -lm -Iinclude -Wall -Wextra -Wshadow  -Wcast-qual


ab : tests/a.c tests/b.c
	cc -std=c99 -o c tests/a.c tests/b.c -lm -Iinclude -Wall -Wextra -Wshadow  -Wcast-qual

bench : benchmarks/bench.c include/xorfilter.h include/binaryfusefilter.h
	cc -std=c99 -O3 -o bench benchmarks/bench.c -lm -Iinclude -Wall -Wextra -Wshadow  -Wcast-qual

test: unit ab
	./unit

clean:
	rm -f unit bench
