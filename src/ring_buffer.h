#pragma once
#include "logger.h"
#include "memory_fixes.h"
#include <cstring>
#include <freertos/FreeRTOS.h>
#include <freertos/ringbuf.h>
#include <stddef.h>
#include <stdint.h>

// Specialized ring buffer for raw byte data (wraps FreeRTOS ringbuffer).
// Supports writeToFront() to put data back at the HEAD of the buffer,
// preserving FIFO order when a write/send is partial or returns EAGAIN.
class DataRingBuffer {
private:
  RingbufHandle_t handle;
  size_t capacity;
  const char *tag;

  // Prepend buffer: holds data that must be read BEFORE the main ring.
  // Used by writeToFront() when a partial write needs to put data back
  // at the front instead of the end (which would break FIFO ordering).
  // Must be >= TransportPump::bufSize_ (default 8192 from ConnectionConfig).
  static constexpr size_t PREPEND_CAP = 8192;
  uint8_t *prepend_ = nullptr;
  size_t prependLen_ = 0;
  size_t prependOff_ = 0;

public:
  DataRingBuffer(size_t size, const char *tagName = "DATA_RING_BUFFER")
      : handle(nullptr), capacity(size), tag(tagName) {
    handle = xRingbufferCreate(capacity, RINGBUF_TYPE_BYTEBUF);
    prepend_ = static_cast<uint8_t *>(safeMalloc(PREPEND_CAP, "prepend"));
    if (!handle || !prepend_) {
      LOGF_E("RING", "Failed to create %s (capacity=%d bytes)", tag, capacity);
      if (handle) {
        vRingbufferDelete(handle);
        handle = nullptr;
      }
      SAFE_FREE(prepend_);
    } else {
      LOGF_I("RING", "Created %s: capacity=%d bytes", tag, capacity);
    }
  }

  ~DataRingBuffer() {
    if (handle) {
      vRingbufferDelete(handle);
      handle = nullptr;
    }
    SAFE_FREE(prepend_);
    LOGF_D("RING", "Destroyed %s", tag);
  }

  // Write data to the END of the buffer (normal append).
  size_t write(const uint8_t *data, size_t len) {
    if (!handle || !data || len == 0)
      return 0;

    size_t written = 0;
    while (written < len) {
      size_t freeSpace = xRingbufferGetCurFreeSize(handle);
      if (freeSpace == 0) {
        break;
      }
      size_t chunk = len - written;
      if (chunk > freeSpace) {
        chunk = freeSpace;
      }
      if (chunk == 0) {
        break;
      }
      BaseType_t ok =
          xRingbufferSend(handle, (void *)(data + written), chunk, 0);
      if (ok != pdTRUE) {
        break;
      }
      written += chunk;
    }
    return written;
  }

  // Write data to the FRONT of the buffer (prepend).
  // Used to put back unsent data so it's read first next time.
  // Returns number of bytes stored (0 if prepend buffer is occupied or too
  // large).
  size_t writeToFront(const uint8_t *data, size_t len) {
    if (!prepend_ || !data || len == 0 || len > PREPEND_CAP)
      return 0;
    // Must not have existing prepend data (caller drains before next
    // writeToFront)
    if (prependLen_ > prependOff_)
      return 0;
    memcpy(prepend_, data, len);
    prependLen_ = len;
    prependOff_ = 0;
    return len;
  }

  // Read data: first drains prepend buffer, then the FreeRTOS ring.
  size_t read(uint8_t *data, size_t len) {
    if (!data || len == 0)
      return 0;

    size_t total = 0;

    // First: drain prepend buffer (data that was put back via writeToFront)
    if (prependLen_ > prependOff_) {
      size_t avail = prependLen_ - prependOff_;
      size_t copy = avail < len ? avail : len;
      memcpy(data, prepend_ + prependOff_, copy);
      prependOff_ += copy;
      total += copy;
      if (prependOff_ >= prependLen_) {
        prependLen_ = 0;
        prependOff_ = 0;
      }
      if (total >= len)
        return total;
    }

    // Then: read from FreeRTOS ring
    if (!handle)
      return total;
    size_t remaining = len - total;
    size_t itemSize = 0;
    uint8_t *item =
        (uint8_t *)xRingbufferReceiveUpTo(handle, &itemSize, 0, remaining);
    if (item) {
      size_t toCopy = itemSize > remaining ? remaining : itemSize;
      memcpy(data + total, item, toCopy);
      vRingbufferReturnItem(handle, item);
      total += toCopy;
    }
    return total;
  }

  void clear() {
    prependLen_ = 0;
    prependOff_ = 0;
    if (!handle)
      return;
    size_t itemSize = 0;
    void *item = nullptr;
    while ((item = xRingbufferReceiveUpTo(handle, &itemSize, 0, capacity)) !=
           nullptr) {
      vRingbufferReturnItem(handle, item);
    }
  }

  size_t size() const {
    size_t prependRemain =
        (prependLen_ > prependOff_) ? (prependLen_ - prependOff_) : 0;
    if (!handle)
      return prependRemain;
    size_t freeSpace = xRingbufferGetCurFreeSize(handle);
    size_t ringUsed = (freeSpace > capacity) ? 0 : (capacity - freeSpace);
    return prependRemain + ringUsed;
  }
  // Available free space for write() (prepend doesn't affect this)
  size_t available() const {
    if (!handle)
      return 0;
    return xRingbufferGetCurFreeSize(handle);
  }
  bool empty() const { return size() == 0; }
  bool full() const { return available() == 0; }
  float usage() const {
    if (capacity == 0)
      return 0.0f;
    return (float)size() / capacity * 100.0f;
  }
  size_t capacityBytes() const { return capacity; }
};
