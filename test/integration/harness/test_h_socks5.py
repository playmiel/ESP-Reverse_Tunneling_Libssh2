"""Test H — SOCKS5 negotiation through the real ESP32 and Docker echo."""
from __future__ import annotations

import socket
import time

from lib import thresholds as TH


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def _send_fragmented(sock: socket.socket, payload: bytes) -> None:
    for byte in payload:
        sock.sendall(bytes((byte,)))
        time.sleep(0.01)


def _negotiate_no_auth(sock: socket.socket) -> None:
    _send_fragmented(sock, b"\x05\x02\x02\x00")
    assert _recv_exact(sock, 2) == b"\x05\x00"


def test_socks5_ipv4_connect_echo(wait_tunnel_ready, tunnel_socket):
    wait_tunnel_ready()
    sock = tunnel_socket(TH.SOCKS5_MAPPING, timeout_s=20.0)
    _negotiate_no_auth(sock)

    address = socket.inet_aton(TH.SOCKS5_TARGET_HOST)
    port = TH.SOCKS5_TARGET_PORT.to_bytes(2, "big")
    _send_fragmented(sock, b"\x05\x01\x00\x01" + address + port)
    response = _recv_exact(sock, 10)
    assert len(response) == 10
    assert response[:4] == b"\x05\x00\x00\x01", response

    payload = b"socks5-through-esp32-and-docker"
    sock.sendall(payload)
    assert _recv_exact(sock, len(payload)) == payload
    sock.close()


def test_socks5_domain_request_echo(wait_tunnel_ready, tunnel_socket):
    """Exercise ATYP=DOMAIN end-to-end using the Docker host text address.

    TEST_SOCKS_DOMAIN_TARGET may provide a real DNS hostname, which the ESP32
    resolves with getaddrinfo(). The default falls back to TEST_DOCKER_HOST_IP
    so the local hardware test remains independent of public DNS while still
    covering the SOCKS domain framing path.
    """
    wait_tunnel_ready()
    sock = tunnel_socket(TH.SOCKS5_MAPPING, timeout_s=20.0)
    _negotiate_no_auth(sock)

    host = TH.SOCKS5_DOMAIN_TARGET.encode("ascii")
    assert 0 < len(host) <= 255
    port = TH.SOCKS5_TARGET_PORT.to_bytes(2, "big")
    request = b"\x05\x01\x00\x03" + bytes((len(host),)) + host + port
    _send_fragmented(sock, request)
    response = _recv_exact(sock, 10)
    assert response[:4] == b"\x05\x00\x00\x01", response

    payload = b"socks5-domain-framing"
    sock.sendall(payload)
    assert _recv_exact(sock, len(payload)) == payload
    sock.close()


def test_socks5_rejects_missing_no_auth(wait_tunnel_ready, tunnel_socket):
    wait_tunnel_ready()
    sock = tunnel_socket(TH.SOCKS5_MAPPING, timeout_s=10.0)
    sock.sendall(b"\x05\x02\x01\x02")
    assert _recv_exact(sock, 2) == b"\x05\xff"
    sock.close()


def test_socks5_rejects_bind_command(wait_tunnel_ready, tunnel_socket):
    wait_tunnel_ready()
    sock = tunnel_socket(TH.SOCKS5_MAPPING, timeout_s=10.0)
    _negotiate_no_auth(sock)
    sock.sendall(b"\x05\x02\x00\x01\x7f\x00\x00\x01\x00\x50")
    response = _recv_exact(sock, 10)
    assert response[:4] == b"\x05\x07\x00\x01", response
    sock.close()


def test_socks5_reports_connection_refused(wait_tunnel_ready, tunnel_socket):
    wait_tunnel_ready()
    sock = tunnel_socket(TH.SOCKS5_MAPPING, timeout_s=10.0)
    _negotiate_no_auth(sock)
    # ESP32 loopback has no service on this high port and rejects immediately;
    # the Windows host may firewall-drop the same request and produce timeout.
    address = socket.inet_aton("127.0.0.1")
    dead_port = (65500).to_bytes(2, "big")
    sock.sendall(b"\x05\x01\x00\x01" + address + dead_port)
    response = _recv_exact(sock, 10)
    assert response[:4] == b"\x05\x05\x00\x01", response
    sock.close()


def test_socks5_negotiation_timeout(wait_tunnel_ready, tunnel_socket):
    wait_tunnel_ready()
    sock = tunnel_socket(TH.SOCKS5_MAPPING, timeout_s=8.0)
    # Send nothing: the ESP32 must reclaim the channel after five seconds.
    assert _recv_exact(sock, 2) == b"\x05\xff"
    sock.close()
