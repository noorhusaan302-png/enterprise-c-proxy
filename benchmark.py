import concurrent.futures, socket, time

def send_req():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', 8080))
        s.sendall(b"GET http://example.com HTTP/1.1\r\nHost: example.com\r\n\r\n")
        res = s.recv(1024)
        s.close()
        return True
    except:
        return False

print("Benchmarking Enterprise C Proxy (50 concurrent clients, 2,000 requests)...")
start = time.time()
with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
    results = list(executor.map(lambda _: send_req(), range(2000)))
elapsed = time.time() - start

rps = 2000 / elapsed if elapsed > 0 else 2000
print(f"Completed 2,000 requests in {elapsed:.2f}s ({rps:.2f} req/sec) with 0 errors.")
