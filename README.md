# Enterprise C HTTP Proxy Server

A multithreaded, event-driven HTTP forward proxy written from scratch in C. It relays client requests to upstream servers and streams responses back, with response caching, per-client rate limiting, domain blacklisting and a live JSON stats endpoint.

## Features

- **Event-driven I/O:** `kqueue`/`kevent` for non-blocking I/O multiplexing, combined with a POSIX worker thread pool.
- **LRU + TTL response cache:** repeat requests are served from memory instead of going upstream.
- **Per-client rate limiting:** token-bucket algorithm keyed by client IP.
- **Blacklisting:** subdomain-aware blocking of domains listed in `blacklist.txt`.
- **Live stats:** a JSON `/stats` endpoint with active connections, cache hit/miss counts and bandwidth.
- **Safety:** tested under AddressSanitizer and ThreadSanitizer, with clean signal handling and socket cleanup.

## Benchmarks

Measured on <YOUR MACHINE, e.g. MacBook Air M2, 8 GB>, 50 concurrent clients, cached responses:

| Metric | Result |
|---|---|
| Throughput (cache hits) | 12,500+ requests/sec |
| Errors | 0 |
| Cache hit latency | < 1 ms |
| Uncached upstream round trip | ~100 ms |

To reproduce:

```bash
<YOUR BENCHMARK COMMAND, e.g. python3 tests/bench.py --clients 50>
```

## Requirements

- macOS or BSD (uses `kqueue`, so it does **not** run on Linux as-is)
- `clang` or `gcc`, `make`, and `python3` for the test scripts

## Build and Run

```bash
make
./proxy <PORT>        # e.g. ./proxy 8080
```

Send a request through the proxy:

```bash
curl -x localhost:<PORT> http://example.com
```

View live stats:

```bash
curl localhost:<PORT>/stats
```

Example `/stats` response:

```json
<PASTE A REAL /stats RESPONSE HERE>
```

## Configuration

- **Blacklist:** add one domain per line to `blacklist.txt`. Subdomains of a listed domain are blocked too.
- **Rate limit and cache settings:** <WHERE THEY ARE SET, e.g. constants at the top of proxy.c>

## Tests

```bash
make test
```

<NUMBER OF TESTS> tests cover <WHAT THEY COVER, e.g. caching, rate limiting, blacklisting, concurrent clients> and pass under both AddressSanitizer and ThreadSanitizer.

## Project Structure

```text
enterprise-c-proxy/
├── proxy.c          # Proxy server, event loop, thread pool
├── Makefile         # Build and test targets
├── blacklist.txt    # Blocked domains
├── tests/           # Python test and benchmark scripts
└── README.md
```

## Limitations

- Plain HTTP only; HTTPS `CONNECT` tunneling is not supported.
- `kqueue` makes it macOS/BSD only. An `epoll` backend would be needed for Linux.

## Tech Stack

C (POSIX), pthreads, mutexes and condition variables, `kqueue`, BSD sockets, Python (tests), Git.
