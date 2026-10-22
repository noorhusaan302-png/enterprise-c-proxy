# C HTTP Caching Proxy Server

A multithreaded, event-driven HTTP forward proxy written from scratch in C. It relays client requests to upstream servers and streams responses back, with an in-memory LRU/TTL response cache, per-client token-bucket rate limiting, subdomain-aware domain blacklisting and a live JSON `/stats` endpoint.

## Features

- **Event-driven I/O:** non-blocking I/O multiplexing with `kqueue`/`kevent`, combined with a POSIX worker thread pool.
- **LRU + TTL response cache:** repeat requests are served from a mutex-protected in-memory cache instead of going upstream.
- **Per-client rate limiting:** token-bucket algorithm keyed by client IP.
- **Blacklisting:** subdomain-aware blocking of domains listed in `blacklist.txt`.
- **Live stats:** JSON `/stats` endpoint with active connections, cache hit/miss counts and bandwidth.
- **Safety:** tested under AddressSanitizer and ThreadSanitizer.

## Benchmarks

Measured on a MacBook Pro 14-inch (Apple M4, 16 GB), 50 concurrent clients:

| Metric | Result |
| :--- | :--- |
| Throughput (cache hits) | 12,500+ requests/sec |
| Errors | 0 |
| Cache hit latency | ~1.85 ms |
| Uncached upstream round trip | ~142 ms |

To reproduce, start the proxy on port 8080, then run:

```bash
python3 tests/bench.py --clients 50 --port 8080
```

## Requirements

- macOS or BSD (uses `kqueue`; it does not run on Linux as-is)
- `clang` or `gcc`, GNU Make, `curl`, Python 3

## Build and Run

```bash
make
./proxy 8080
```

Forward a request through the proxy:

```bash
curl -i -x localhost:8080 http://example.com
```

View live stats:

```bash
curl -s localhost:8080/stats
```

Example `/stats` response (format only; your values will differ):

```json
{
  "uptime_seconds": 3600,
  "active_connections": 14,
  "total_requests": 128450,
  "cache_hits": 98210,
  "cache_misses": 30240
}
```

## Configuration

- **Blacklist:** add one domain per line to `blacklist.txt`. Subdomains of a listed domain are blocked too.
- **Cache and rate-limit settings:** set as constants at the top of `proxy.c`.

## Tests

```bash
make test
```

14 tests cover the LRU cache and TTL expiry, token-bucket rate limiting, blacklist matching and concurrent clients, and they pass under AddressSanitizer and ThreadSanitizer.

## Project Structure

```text
├── proxy.c          # Proxy server, event loop, thread pool, cache
├── Makefile         # Build and test targets
├── blacklist.txt    # Blocked domains
├── tests/           # Python test and benchmark scripts
└── README.md
```

## Limitations

- Plain HTTP only; HTTPS `CONNECT` tunneling is not supported.
- macOS/BSD only; Linux would need an `epoll` backend.
- The cache lives in memory and does not persist across restarts.

## Tech Stack

C (POSIX), pthreads, mutexes and condition variables, `kqueue`, BSD sockets, Python (tests), Git.
