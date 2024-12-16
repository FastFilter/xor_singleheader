all: unit bench

unit : tests/unit.c include/xorfilter.h include/binaryfusefilter.h
	${CC} -std=c99 -g -O2 -fsanitize=address,leak,undefined -o unit tests/unit.c -lm -Iinclude -Wall -Wextra -Wshadow  -Wcast-qual -Wconversion -Wsign-conversion -Werror

ab : tests/a.c tests/b.c
	${CC} -std=c99 -o c tests/a.c tests/b.c -lm -Iinclude -Wall -Wextra -Wshadow  -Wcast-qual -Wconversion -Wsign-conversion

bench : benchmarks/bench.c include/xorfilter.h include/binaryfusefilter.h
	${CC} -std=c99 -O3 -o bench benchmarks/bench.c -lm -Iinclude -Wall -Wextra -Wshadow  -Wcast-qual -Wconversion -Wsign-conversion

test: unit ab
	ASAN_OPTIONS='halt_on_error=1:abort_on_error=1:print_summary=1' \
	UBSAN_OPTIONS='halt_on_error=1:abort_on_error=1:print_summary=1:print_stacktrace=1' \
	./unit

clean:
	rm -f unit bench
