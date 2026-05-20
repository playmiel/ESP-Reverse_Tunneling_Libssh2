#!/usr/bin/env python3
"""Slow TCP echo server: echoes received bytes throttled to ~1 KB/s.

Used by integration test G2 (backpressure) to verify that a slow
consumer on one channel does not destabilize the SSH session or
starve other channels.
"""
import socket
import threading
import time

HOST = "0.0.0.0"
PORT = 9001
RATE_BYTES_PER_SEC = 1024
CHUNK = 64


def handle(conn, addr):
    print(f"[slow_echo] connect from {addr}", flush=True)
    try:
        conn.settimeout(60.0)
        while True:
            data = conn.recv(4096)
            if not data:
                break
            for i in range(0, len(data), CHUNK):
                piece = data[i:i + CHUNK]
                conn.sendall(piece)
                time.sleep(len(piece) / RATE_BYTES_PER_SEC)
    except (socket.timeout, ConnectionResetError, BrokenPipeError) as e:
        print(f"[slow_echo] {addr} closed: {e}", flush=True)
    finally:
        conn.close()
        print(f"[slow_echo] disconnect {addr}", flush=True)


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(8)
    print(f"[slow_echo] listening on {HOST}:{PORT}", flush=True)
    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        srv.close()


if __name__ == "__main__":
    main()
