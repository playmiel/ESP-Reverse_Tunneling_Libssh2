"""Deterministic byte-stream generator + verifier (xorshift32).

Reproducible across platforms — does not use Python's random module.
"""
from __future__ import annotations


def _xorshift32(state: int) -> int:
    state ^= (state << 13) & 0xFFFFFFFF
    state ^= (state >> 17) & 0xFFFFFFFF
    state ^= (state << 5) & 0xFFFFFFFF
    return state & 0xFFFFFFFF


def make_stream(seed: int, length: int) -> bytes:
    """Produce a deterministic byte sequence of `length` bytes from `seed`."""
    out = bytearray(length)
    state = seed & 0xFFFFFFFF
    if state == 0:
        state = 1
    i = 0
    while i + 4 <= length:
        state = _xorshift32(state)
        out[i] = state & 0xFF
        out[i + 1] = (state >> 8) & 0xFF
        out[i + 2] = (state >> 16) & 0xFF
        out[i + 3] = (state >> 24) & 0xFF
        i += 4
    while i < length:
        state = _xorshift32(state)
        out[i] = state & 0xFF
        i += 1
    return bytes(out)


def verify_stream(seed: int, received: bytes) -> tuple[int, int]:
    """Compare received bytes against the deterministic stream.

    Returns (mismatches, first_mismatch_offset). first_mismatch_offset is -1
    if no mismatch.
    """
    expected = make_stream(seed, len(received))
    if expected == received:
        return (0, -1)
    mismatches = 0
    first = -1
    for i, (e, r) in enumerate(zip(expected, received)):
        if e != r:
            mismatches += 1
            if first < 0:
                first = i
    return (mismatches, first)
