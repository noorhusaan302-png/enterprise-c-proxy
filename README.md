# Enterprise C HTTP Proxy Server

A high-performance, concurrent, event-driven HTTP proxy server built completely from scratch in modern C. Designed with systems-level networking primitives, this project emphasizes low latency, robust concurrency, and efficient resource management.

## 🚀 Key Features

* **Event-Driven Architecture:** Utilizes macOS `kqueue` for high-throughput, non-I/O multiplexing alongside a multi-threaded POSIX worker pool.
* **Smart Caching:** Integrated LRU (Least Recently Used) and TTL (Time-To-Live) caching mechanism to accelerate frequent proxy responses.
* **Rate Limiting:** Token-bucket rate-limiting algorithm implemented per client IP to safeguard against traffic spikes and abuse.
* **Access Control & Blacklisting:** Dynamic blacklist checking to block forbidden domains or restricted endpoints.
* **Real-Time Monitoring:** Built-in JSON `/stats` endpoint exposing live performance metrics, active connections, cache hit/miss ratios, and bandwidth usage.
* **Robust Error Handling:** Comprehensive socket lifecycle management, clean signal handling, and secure request/response parsing.

---

## 🛠️ Project Stack

* **Language:** C (POSIX standard)
* **Concurrency:** POSIX Threads (`pthreads`), Mutexes/Condition Variables
* **Multiplexing:** `kqueue` / `kevent` (Optimized for macOS / BSD systems)
* **Networking:** Low-level socket APIs (`sys/socket.h`, `netinet/in.h`)
* **Version Control:** Git / GitHub

---

## 📂 Project Structure

```text
enterprise-c-proxy/
├── proxy.c          # Core proxy server implementation, event loop, and thread pool
├── Makefile         # Build automation configuration
├── blacklist.txt    # Configurable list of blocked domains/IPs
└── README.md        # Project documentation
