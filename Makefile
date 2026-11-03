CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra
LDLIBS  := -lpthread

# kqueue is native on macOS/BSD. On Linux, builds work with libkqueue
# (apt install libkqueue-dev), which is handy for CI.
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
  CFLAGS += -I/usr/include/kqueue
  LDLIBS += -lkqueue
endif

SAN_FLAGS := -g -O1 -fno-omit-frame-pointer

.PHONY: all test test-asan test-tsan bench clean

all: proxy

proxy: proxy.c
	$(CC) $(CFLAGS) proxy.c -o proxy $(LDLIBS)

# AddressSanitizer + UndefinedBehaviorSanitizer build
proxy-asan: proxy.c
	$(CC) $(CFLAGS) $(SAN_FLAGS) -fsanitize=address,undefined proxy.c -o proxy-asan $(LDLIBS)

# ThreadSanitizer build
proxy-tsan: proxy.c
	$(CC) $(CFLAGS) $(SAN_FLAGS) -fsanitize=thread proxy.c -o proxy-tsan $(LDLIBS)

# Run the full test suite against both sanitizer builds
test: test-asan test-tsan

test-asan: proxy-asan
	PROXY_BIN=./proxy-asan python3 tests/test_proxy.py

test-tsan: proxy-tsan
	PROXY_BIN=./proxy-tsan python3 tests/test_proxy.py

bench: proxy
	@echo "Start the proxy first, e.g.: PROXY_MAX_TOKENS=1000000 ./proxy 8080"
	python3 tests/bench.py --clients 50 --port 8080

clean:
	rm -f proxy proxy-asan proxy-tsan
