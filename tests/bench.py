#!/usr/bin/env python3
"""
Load benchmark for the C HTTP caching proxy.

Start the proxy first. The default token bucket (10 requests, 2/sec refill)
would rate-limit a load test from a single IP, so raise it for benchmarking:

    PROXY_MAX_TOKENS=1000000 PROXY_REFILL_RATE=1000000 ./proxy 8080
    python3 tests/bench.py --clients 50 --port 8080

It measures:
  - uncached upstream round trip (first request for each URL)
  - cache hit latency (median and p99)
  - throughput of cache hits with N concurrent clients
  - errors (anything that is not a 200 response, timeouts and resets)
"""
import argparse
import socket
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit


def request(port, host, path, timeout=10):
    """Send one GET through the proxy; return (status, seconds)."""
    start = time.perf_counter()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
            s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
            data = b""
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
        status = int(data.split(b" ", 2)[1]) if data.startswith(b"HTTP/") else 0
    except (OSError, ValueError, IndexError):
        status = 0
    return status, time.perf_counter() - start


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--clients", type=int, default=50, help="concurrent clients")
    ap.add_argument("--requests", type=int, default=200, help="requests per client")
    ap.add_argument("--port", type=int, default=8080, help="proxy port")
    ap.add_argument("--url", default="http://example.com/", help="URL to fetch")
    args = ap.parse_args()

    parts = urlsplit(args.url)
    host = parts.netloc
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query

    # 1) Uncached round trip: a unique path is always a cache miss
    miss_times = []
    for i in range(5):
        sep = "&" if "?" in path else "?"
        status, t = request(args.port, host, f"{path}{sep}bench_miss={time.time_ns()}_{i}")
        if status == 200:
            miss_times.append(t)

    # 2) Warm the cache for the benchmark URL
    status, _ = request(args.port, host, path)
    if status != 200:
        raise SystemExit(f"warm-up request failed with status {status}; is the proxy running "
                         f"on port {args.port} with a raised rate limit?")

    # 3) Concurrent cache hits
    total = args.clients * args.requests

    def client(_):
        return [request(args.port, host, path) for _ in range(args.requests)]

    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.clients) as pool:
        results = [r for batch in pool.map(client, range(args.clients)) for r in batch]
    elapsed = time.perf_counter() - start

    ok_times = sorted(t for s, t in results if s == 200)
    errors = total - len(ok_times)

    print(f"Clients: {args.clients}   Requests: {total}   URL: {args.url}")
    print(f"Throughput (cache hits):      {total / elapsed:,.0f} requests/sec")
    print(f"Errors:                       {errors}")
    if ok_times:
        p99 = ok_times[min(len(ok_times) - 1, int(len(ok_times) * 0.99))]
        print(f"Cache hit latency (median):   {statistics.median(ok_times) * 1000:.2f} ms")
        print(f"Cache hit latency (p99):      {p99 * 1000:.2f} ms")
    if miss_times:
        print(f"Uncached upstream round trip: {statistics.median(miss_times) * 1000:.0f} ms")
    else:
        print("Uncached upstream round trip: n/a (no successful uncached requests)")


if __name__ == "__main__":
    main()
