#ifndef PREPEND_BUFFER_H
#define PREPEND_BUFFER_H

#include <cstddef>
#include <cstdint>
#include <cstring>

// Holds data that must be read BEFORE the main ring. Used to put back
// bytes that a partial write returned via EAGAIN, preserving FIFO order.
//
// PrependBuffer does NOT own its storage — the caller passes a pointer
// + capacity at construction (or via reset()). This lets DataRingBuffer
// keep using PSRAM for the backing memory while the logic stays a pure,
// host-testable, non-FreeRTOS class.
class PrependBuffer {
public:
    PrependBuffer() = default;
    PrependBuffer(uint8_t* storage, size_t capacity)
        : buf_(storage), cap_(capacity) {}

    // (Re-)bind to a (possibly new) backing storage. Resets read/write state.
    void reset(uint8_t* storage, size_t capacity) {
        buf_ = storage;
        cap_ = capacity;
        len_ = 0;
        off_ = 0;
    }

    // Returns number of bytes stored, or 0 on rejection.
    // Rejected if: no storage bound, data null/zero-length, len > capacity,
    // or buffer not yet drained.
    size_t writeToFront(const uint8_t* data, size_t len) {
        if (!buf_ || !data || len == 0 || len > cap_) return 0;
        if (len_ > off_) return 0;  // not drained
        std::memcpy(buf_, data, len);
        len_ = len;
        off_ = 0;
        return len;
    }

    // Read up to `len` bytes, returns actual number read.
    size_t read(uint8_t* out, size_t len) {
        if (!buf_ || !out || len == 0 || len_ <= off_) return 0;
        size_t avail = len_ - off_;
        size_t copy = avail < len ? avail : len;
        std::memcpy(out, buf_ + off_, copy);
        off_ += copy;
        if (off_ >= len_) {
            len_ = 0;
            off_ = 0;
        }
        return copy;
    }

    bool empty() const { return len_ <= off_; }
    size_t pending() const { return (len_ > off_) ? (len_ - off_) : 0; }
    size_t capacity() const { return cap_; }
    bool isBound() const { return buf_ != nullptr; }

    void clear() { len_ = 0; off_ = 0; }

private:
    uint8_t* buf_ = nullptr;
    size_t cap_ = 0;
    size_t len_ = 0;
    size_t off_ = 0;
};

#endif // PREPEND_BUFFER_H
