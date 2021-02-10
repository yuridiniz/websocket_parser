SRC = $(wildcard src/*.c)
DEPS = $(wildcard deps/*/*.c)
TEST = test/test.c
BENCH = test/bench.c

test: FORCE
	@ $(CC) -O3 -std=c99 $(TEST) $(SRC) $(DEPS) -o test/test.out -Ideps -Isrc
	@ ./test/test.out

benchmark: FORCE
	@ $(CC) -O3 -std=c99 $(BENCH) $(SRC) $(DEPS) -o test/bench.out -Ideps -Isrc
	@ ./test/bench.out

FORCE: