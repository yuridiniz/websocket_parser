SRC = $(wildcard src/*.c)
DEPS = $(wildcard deps/*/*.c)
TEST_DEPS = $(wildcard test/deps/*/*.c)

TEST = test/test.c
BENCH = test/bench.c

all: test benchmark

test: FORCE
	@ $(CC) -g -D_WS_TEST_MOCK -std=c99 $(TEST) $(SRC) $(DEPS) $(TEST_DEPS) -o test/test.out -Ideps -Itest/deps -Isrc 
	@ ./test/test.out

benchmark: FORCE
	@ $(CC) -O3 -D_WS_TEST_MOCK -std=c99 $(BENCH) $(SRC) $(DEPS) $(TEST_DEPS) -o test/bench.out -Ideps -Itest/deps -Isrc
	@ ./test/bench.out

FORCE: