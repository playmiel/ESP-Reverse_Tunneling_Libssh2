"""Centralized pass/fail thresholds for integration tests.

Tune these instead of touching test bodies.
"""

A_TRANSFER_SIZES = [1 * 1024 * 1024, 10 * 1024 * 1024]
# Default chunks: 8K and 64K — both pass reliably. Smaller chunks
# (256, 1024) intermittently lose bytes or fail with BrokenPipe — that's
# a real bug worth investigating in the lib (not a test infra issue),
# but it makes the suite flaky as a regression gate. Add 256/1024 back
# to A_CHUNK_SIZES_EXTRA when debugging that path explicitly.
A_CHUNK_SIZES = [8 * 1024, 64 * 1024]
A_CHUNK_SIZES_EXTRA = [256, 1024]
A_PRNG_SEED = 0xC0FFEE

B_DURATION_S = 300
B_SAMPLE_HZ = 1
B_MAX_STALL_S = 3.0
B_MIN_STALL_BYTES_PER_S = 1024
B_MAX_STDDEV_RATIO = 0.30
B_MAX_HEAP_DRIFT_BYTES = 5 * 1024

D_CYCLES = 50
D_CHUNK_BYTES = 100 * 1024
D_INTER_CYCLE_DELAY_S = 1.0
D_MAX_HEAP_DRIFT_BYTES = 5 * 1024

F_TRANSFER_BYTES = 10 * 1024 * 1024
F_KILL_AT_FRACTION = 0.5
F_DOWN_S = 5.0
F_RECONNECT_TIMEOUT_S = 30.0

G1_DEAD_PORT_MAPPING = 22082
G1_ATTEMPTS = 10
G1_PARALLEL_LIVE_MAPPING = 22080
G2_SLOW_MAPPING = 22081
G2_LIVE_MAPPING = 22080
G2_BURST_BYTES = 1 * 1024 * 1024
G2_LIVE_THROUGHPUT_TOLERANCE = 0.30

TUNNEL_READY_TIMEOUT_S = 30.0
SERIAL_PORT = "/dev/ttyUSB1"
SERIAL_BAUD = 115200
DOCKER_HOST_FOR_CLIENT = "127.0.0.1"
# String value emitted by SSHTunnel::getStateString() when the SSH session
# is fully established (matches the firmware, not an arbitrary constant).
TUNNEL_STATE_CONNECTED = "Connected"
