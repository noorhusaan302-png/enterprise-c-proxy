# C HTTP Caching Proxy Server

A multithreaded HTTP/HTTPS forward proxy written from scratch in C. It relays client requests to upstream servers and streams responses back, with an in-memory LRU + TTL response cache, upstream connection pooling, per-client token-bucket rate limiting, subdomain-aware domain blacklisting, HTTPS `CONNECT` tunneling, and a live JSON `/stats` endpoint.

## Features

- **Thread-per-connection concurrency:** each accepted client is handled on its own POSIX thread (`pthread_create`), with shared state protected by mutexes.
- **HTTPS tunneling:** handles `CONNECT` requests and relays encrypted traffic in both directions, using `kqueue`/`kevent` to watch the client and upstream sockets at the same time.
- **LRU + TTL response cache:** repeat requests are served from a mutex-protected in-memory cache. A cache hit moves the entry to the front, the least recently used entry is evicted when the cache is full, and entries expire after a TTL.
- **Upstream connection pooling:** reuses open sockets to the same host instead of reconnecting for every request.
- **Per-client rate limiting:** token-bucket algorithm keyed by client IP.
- **Blacklisting:** subdomain-aware blocking of domains listed in `blacklist.txt` (returns 403 Forbidden).
- **Live stats:** JSON `/stats` endpoint with request, cache-hit, blocked, rate-limited, connection-reuse and bytes-proxied counters.

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
python3 benchmark.py
```

## Requirements

- macOS or BSD (uses `kqueue`; it does not run on Linux as-is)
- `gcc` or `clang`, GNU Make, `curl`, Python 3

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

Example `/stats` response (your values will differ):

```json
{
  "total_requests": 128450,
  "cache_hits": 98210,
  "blocked_requests": 37,
  "rate_limited_requests": 512,
  "pooled_connections_reused": 20415,
  "total_bytes_proxied": 734003200
}
```

## Configuration

- **Blacklist:** add one domain per line to `blacklist.txt`. Subdomains of a listed domain are blocked too.
- **Cache and rate-limit settings:** set as constants at the top of `proxy.c` (`MAX_CACHE_SIZE`, `CACHE_TTL`, `MAX_TOKENS`, `REFILL_RATE`).

## Project Structure

```text
├── proxy.c          # Proxy server: request handling, CONNECT tunnel, cache, pool, rate limiter, stats
├── Makefile         # Build target
├── blacklist.txt    # Blocked domains
├── benchmark.py     # 50-client load benchmark
├── test_suite.py    # Test runner (work in progress)
└── README.md
```

## Limitations

- macOS/BSD only; Linux would need an `epoll` backend.
- One thread per connection, so very high connection counts are bounded by thread overhead.
- The cache lives in memory and does not persist across restarts.
- Automated tests are still in progress.

## Tech Stack

C (POSIX), pthreads, mutexes, `kqueue`, BSD sockets, Python (benchmark), Git.
