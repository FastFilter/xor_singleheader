unit : tests/unit.c include/xorfilter.h
	cc -O3 -o unit tests/unit.c -Iinclude -Wall -Wextra -Wshadow  -Wcast-qual

test: unit
	./unit

clean: 
	rm -f unit
