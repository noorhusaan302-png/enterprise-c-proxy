#!/usr/bin/env python3
"""
Integration tests for the C HTTP caching proxy.

Each test starts a fresh proxy process (so cache, rate-limit and metric state
never leak between tests) in front of a local upstream HTTP server, sends real
HTTP requests through it, and checks the behavior from the outside.

The proxy binary comes from $PROXY_BIN (default ./proxy). `make test` runs the
whole suite against an AddressSanitizer build and a ThreadSanitizer build; any
sanitizer report in the proxy's stderr fails the test that triggered it.

Run directly:   PROXY_BIN=./proxy python3 tests/test_proxy.py
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PROXY_BIN = os.path.abspath(os.environ.get("PROXY_BIN", os.path.join(REPO_ROOT, "proxy")))

SANITIZER_MARKERS = (
    "ERROR: AddressSanitizer",
    "WARNING: ThreadSanitizer",
    "runtime error:",          # UndefinedBehaviorSanitizer
    "ERROR: LeakSanitizer",
)

CACHE_SIZE = 5  # MAX_CACHE_SIZE in proxy.c


# ---------------------------------------------------------------------------
# Local upstream server
# ---------------------------------------------------------------------------
class Upstream:
    """A small keep-alive HTTP/1.1 server that records every request it gets."""

    def __init__(self):
        self.hits = {}           # path -> number of requests that reached upstream
        self.headers = []        # list of header dicts, in arrival order
        self.lock = threading.Lock()
        upstream = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def _record(self):
                with upstream.lock:
                    upstream.hits[self.path] = upstream.hits.get(self.path, 0) + 1
                    upstream.headers.append(dict(self.headers))
                    return upstream.hits[self.path]

            def _reply(self, status, body):
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                n = self._record()
                if self.path.startswith("/status/404"):
                    self._reply(404, "not found")
                else:
                    self._reply(200, f"upstream {self.path} #{n}")

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(length)
                n = self._record()
                self._reply(200, f"posted {self.path} #{n}")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def count(self, path):
        with self.lock:
            return self.hits.get(path, 0)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def http_request(proxy_port, host, path, method="GET", body=b"", timeout=10):
    """Send one request through the proxy; return (status, headers_text, body)."""
    req = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
    if body:
        req += f"Content-Length: {len(body)}\r\n"
    req = req.encode() + b"\r\n" + body

    with socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout) as s:
        s.sendall(req)
        chunks = []
        while True:
            data = s.recv(65536)
            if not data:
                break
            chunks.append(data)
    raw = b"".join(chunks)
    head, _, rest = raw.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].decode(errors="replace")
    status = int(status_line.split()[1]) if len(status_line.split()) > 1 else 0
    return status, head.decode(errors="replace"), rest


class ProxyTestCase(unittest.TestCase):
    """Starts a fresh upstream + proxy for every test."""

    # Default settings for tests: effectively no rate limit, 60s cache TTL
    proxy_env = {"PROXY_MAX_TOKENS": "1000000000", "PROXY_REFILL_RATE": "1000000"}
    blacklist = "blocked.test\n27.0.0.1\n"

    def setUp(self):
        self.upstream = Upstream()
        self.workdir = tempfile.mkdtemp(prefix="proxytest-")
        with open(os.path.join(self.workdir, "blacklist.txt"), "w") as f:
            f.write(self.blacklist)
        self.start_proxy(dict(self.proxy_env))

    def start_proxy(self, extra_env):
        env = dict(os.environ)
        env.update(extra_env)
        env.setdefault("ASAN_OPTIONS", "abort_on_error=0:detect_leaks=0")
        env.setdefault("TSAN_OPTIONS", "halt_on_error=0")
        self.port = free_port()
        self.stderr_path = os.path.join(self.workdir, "proxy.stderr")
        self.stderr_file = open(self.stderr_path, "w")
        self.proc = subprocess.Popen(
            [PROXY_BIN, str(self.port)], cwd=self.workdir, env=env,
            stdout=subprocess.DEVNULL, stderr=self.stderr_file)
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return
            except OSError:
                if self.proc.poll() is not None:
                    break
                time.sleep(0.05)
        self.fail(f"proxy did not start:\n{self.read_stderr()}")

    def read_stderr(self):
        if not self.stderr_file.closed:
            self.stderr_file.flush()
        with open(self.stderr_path) as f:
            return f.read()

    def tearDown(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.stderr_file.close()
        stderr = self.read_stderr()
        self.upstream.stop()
        shutil.rmtree(self.workdir, ignore_errors=True)
        for marker in SANITIZER_MARKERS:
            if marker in stderr:
                self.fail(f"sanitizer report from proxy:\n{stderr}")

    # Shorthand for a request to the local upstream through the proxy
    def get(self, path, method="GET", body=b""):
        return http_request(self.port, f"127.0.0.1:{self.upstream.port}", path, method, body)

    def stats(self):
        status, _, body = http_request(self.port, f"127.0.0.1:{self.port}", "/stats")
        self.assertEqual(status, 200)
        return json.loads(body)


# ---------------------------------------------------------------------------
# Forwarding
# ---------------------------------------------------------------------------
class ForwardingTests(ProxyTestCase):
    def test_01_forwards_request_to_upstream(self):
        status, _, body = self.get("/hello")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"upstream /hello #1")
        self.assertEqual(self.upstream.count("/hello"), 1)

    def test_02_injects_proxy_header(self):
        self.get("/header-check")
        self.assertEqual(self.upstream.headers[-1].get("X-Proxied-By"),
                         "CustomCProxy-RateLimited")


# ---------------------------------------------------------------------------
# LRU + TTL cache
# ---------------------------------------------------------------------------
class CacheTests(ProxyTestCase):
    def test_03_cache_hit_skips_upstream(self):
        first = self.get("/cached")
        second = self.get("/cached")
        self.assertEqual(first[0], 200)
        self.assertEqual(second[2], first[2])          # identical body from cache
        self.assertEqual(self.upstream.count("/cached"), 1)

    def test_04_post_requests_are_not_cached(self):
        self.get("/form", method="POST", body=b"a=1")
        self.get("/form", method="POST", body=b"a=1")
        self.assertEqual(self.upstream.count("/form"), 2)

    def test_05_lru_evicts_least_recently_used(self):
        for i in range(CACHE_SIZE + 1):              # one more than fits
            self.get(f"/lru/{i}")
        self.get(f"/lru/{CACHE_SIZE}")              # newest entry: still cached
        self.assertEqual(self.upstream.count(f"/lru/{CACHE_SIZE}"), 1)
        self.get("/lru/0")                           # oldest entry: evicted
        self.assertEqual(self.upstream.count("/lru/0"), 2)

    def test_06_cache_hit_refreshes_recency(self):
        for i in range(CACHE_SIZE):
            self.get(f"/r/{i}")
        self.get("/r/0")                             # hit moves /r/0 to the front
        self.get(f"/r/{CACHE_SIZE}")                 # evicts /r/1, not /r/0
        self.get("/r/0")
        self.assertEqual(self.upstream.count("/r/0"), 1)
        self.get("/r/1")
        self.assertEqual(self.upstream.count("/r/1"), 2)


class TTLTests(ProxyTestCase):
    proxy_env = dict(ProxyTestCase.proxy_env, PROXY_CACHE_TTL="1")

    def test_07_ttl_expiry_refetches(self):
        self.get("/ttl")
        self.get("/ttl")
        self.assertEqual(self.upstream.count("/ttl"), 1)
        time.sleep(2.2)
        self.get("/ttl")
        self.assertEqual(self.upstream.count("/ttl"), 2)


# ---------------------------------------------------------------------------
# Token-bucket rate limiting
# ---------------------------------------------------------------------------
class RateLimitTests(ProxyTestCase):
    proxy_env = {"PROXY_MAX_TOKENS": "3", "PROXY_REFILL_RATE": "0.001"}

    def test_08_returns_429_when_bucket_is_empty(self):
        statuses = [self.get(f"/rl/{i}")[0] for i in range(5)]
        self.assertEqual(statuses[:3], [200, 200, 200])
        self.assertEqual(statuses[3:], [429, 429])
        self.assertEqual(self.upstream.count("/rl/3"), 0)


class RefillTests(ProxyTestCase):
    proxy_env = {"PROXY_MAX_TOKENS": "2", "PROXY_REFILL_RATE": "4"}

    def test_09_bucket_refills_over_time(self):
        self.assertEqual(self.get("/a")[0], 200)
        self.assertEqual(self.get("/b")[0], 200)
        self.assertEqual(self.get("/c")[0], 429)
        time.sleep(0.6)                              # 4 tokens/s -> ~2 tokens back
        self.assertEqual(self.get("/d")[0], 200)


# ---------------------------------------------------------------------------
# Blacklist
# ---------------------------------------------------------------------------
class BlacklistTests(ProxyTestCase):
    def test_10_blocks_exact_domain(self):
        status, _, body = http_request(self.port, "blocked.test", "/")
        self.assertEqual(status, 403)
        self.assertIn(b"403 Forbidden", body)

    def test_11_blocks_subdomains_only_on_label_boundary(self):
        status, _, _ = http_request(self.port, "ads.blocked.test", "/")
        self.assertEqual(status, 403)
        # "27.0.0.1" is listed, but "127.0.0.1" is a different name, not a subdomain
        status, _, _ = self.get("/not-blocked")
        self.assertEqual(status, 200)


# ---------------------------------------------------------------------------
# Stats, connection pool, concurrency
# ---------------------------------------------------------------------------
class StatsAndPoolTests(ProxyTestCase):
    def test_12_stats_endpoint_reports_metrics(self):
        self.get("/s")      # miss
        self.get("/s")      # hit
        http_request(self.port, "blocked.test", "/")
        s = self.stats()
        for key in ("uptime_seconds", "active_connections", "total_requests",
                    "cache_hits", "cache_misses", "blocked_requests",
                    "rate_limited_requests", "pooled_connections_reused",
                    "total_bytes_proxied", "bandwidth_bytes_per_sec"):
            self.assertIn(key, s)
        self.assertEqual(s["cache_hits"], 1)
        self.assertEqual(s["cache_misses"], 1)
        self.assertEqual(s["blocked_requests"], 1)
        self.assertGreaterEqual(s["active_connections"], 1)   # the /stats request itself
        self.assertGreater(s["total_bytes_proxied"], 0)

    def test_13_reuses_pooled_upstream_connections(self):
        self.get("/pool/1")
        self.get("/pool/2")                          # different path -> cache miss
        self.assertGreaterEqual(self.stats()["pooled_connections_reused"], 1)


class ConcurrencyTests(ProxyTestCase):
    def test_14_handles_50_concurrent_clients(self):
        def worker(i):
            return [self.get(f"/load/{(i * 10 + j) % 13}")[0] for j in range(10)]

        with ThreadPoolExecutor(max_workers=50) as pool:
            results = [s for batch in pool.map(worker, range(50)) for s in batch]
        self.assertEqual(len(results), 500)
        self.assertEqual(results.count(200), 500)
        time.sleep(0.3)
        self.assertEqual(self.stats()["active_connections"], 1)  # only /stats left


if __name__ == "__main__":
    if not os.path.exists(PROXY_BIN):
        sys.exit(f"proxy binary not found: {PROXY_BIN} (run `make` first)")
    print(f"Testing {os.path.relpath(PROXY_BIN, os.getcwd())}")
    unittest.main(verbosity=2)
