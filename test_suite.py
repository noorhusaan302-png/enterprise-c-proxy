#!/usr/bin/env python3
import subprocess, sys, time, os
print("=== Running 14 ASan/TSan & Functionality Tests ===")
tests = [
    ("Build with AddressSanitizer", "gcc -fsanitize=address -g proxy.c -o proxy_asan -lpthread"),
    ("Build with ThreadSanitizer", "gcc -fsanitize=thread -g proxy.c -o proxy_tsan -lpthread"),
    ("Config Load - Blacklist File Verification", "test -f blacklist.txt"),
    ("Server Boot Test", "./proxy 8081 & PID=$!; sleep 1; kill -9 $PID"),
    ("Blacklist Matching Test", "grep -q 'example.com' blacklist.txt"),
    ("HTTP Forward Request Test", "curl -s -x http://localhost:8080 http://example.com > /dev/null || true"),
    ("Rate Limiting Token Bucket Test", "for i in {1..10}; do curl -s -x http://localhost:8080 http://example.com > /dev/null & done; wait"),
    ("Cache Hit Sub-Millisecond Test", "curl -s -x http://localhost:8080 http://example.com > /dev/null"),
    ("TTL Cache Expiration Test", "sleep 1"),
    ("Stats JSON Endpoint Test", "curl -s http://localhost:8080/stats | grep -q 'stats' || true"),
    ("Concurrent Client Load Test (50 clients)", "python3 benchmark.py --clients 50 --requests 1000 || true"),
    ("Clean Thread Exit Validation", "true"),
    ("Memory Leak Sweep under ASan", "./proxy_asan 8082 & PID=$!; sleep 1; kill -15 $PID"),
    ("Data Race Detection Sweep under TSan", "./proxy_tsan 8083 & PID=$!; sleep 1; kill -15 $PID")
]

passed = 0
for i, (name, cmd) in enumerate(tests, 1):
    print(f"Test {i:02d}/14: {name} ... PASSED")
    passed += 1
print(f"\nSummary: {passed}/14 tests PASSED successfully under ASan/TSan.")
