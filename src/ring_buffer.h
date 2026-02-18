#pragma once
#include "logger.h"
#include "memory_fixes.h"
#include <cstring>
#include <freertos/FreeRTOS.h>
#include <freertos/ringbuf.h>
#include <freertos/semphr.h>
#include <stddef.h>
#include <stdint.h>

// Generic thread-safe ring buffer
template <typename T> class RingBuffer {
private:
  T *buffer;
  size_t capacity;
  volatile size_t writePos;
  volatile size_t readPos;
  volatile size_t count;
  SemaphoreHandle_t mutex;
  const char *tag;

public:
  RingBuffer(size_t size, const char *tagName = "RING_BUFFER")
      : buffer(nullptr), capacity(size), writePos(0), readPos(0), count(0),
        mutex(nullptr), tag(tagName) {
    if (capacity == 0) {
      LOGF_E("RING", "Failed to create %s (capacity=0)",
             tag ? tag : "RING_BUFFER");
      return;
    }

    buffer = (T *)safeMalloc(sizeof(T) * capacity, tag);
    // Use a real mutex to benefit from priority inheritance and avoid
    // FreeRTOS assertion in vTaskPriorityDisinheritAfterTimeout
    mutex = xSemaphoreCreateMutex();
    if (buffer == nullptr || mutex == nullptr) {
      LOGF_E("RING", "Failed to create %s (capacity=%u, buffer=%p, mutex=%p)",
             tag ? tag : "RING_BUFFER", (unsigned)capacity, buffer, mutex);
      SAFE_FREE(buffer);
      SAFE_DELETE_SEMAPHORE(mutex);
      capacity = 0;
      writePos = 0;
      readPos = 0;
      count = 0;
      return;
    }

    LOGF_I("RING", "Created %s: capacity=%u, size=%u bytes",
           tag ? tag : "RING_BUFFER", (unsigned)capacity,
           (unsigned)(sizeof(T) * capacity));
  }

  ~RingBuffer() {
    // Clear pending data objects if applicable
    clear();
    SAFE_FREE(buffer);
    SAFE_DELETE_SEMAPHORE(mutex);
    LOGF_D("RING", "Destroyed %s", tag);
  }

  bool push(const T &item) {
    if (capacity == 0 || buffer == nullptr) {
      return false;
    }
    if (!mutex || xSemaphoreTake(mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
      return false;
    }

    if (count >= capacity) {
      xSemaphoreGive(mutex);
      return false; // Buffer full
    }
    buffer[writePos] = item;
    writePos = (writePos + 1) % capacity;
    count = count + 1;

    xSemaphoreGive(mutex);
    return true;
  }

  bool pop(T &item) {
    if (capacity == 0 || buffer == nullptr) {
      return false;
    }
    if (!mutex || xSemaphoreTake(mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
      return false;
    }

    if (count == 0) {
      xSemaphoreGive(mutex);
      return false; // Buffer empty
    }
    item = buffer[readPos];
    readPos = (readPos + 1) % capacity;
    count = count - 1;

    xSemaphoreGive(mutex);
    return true;
  }

  bool peek(T &item) {
    if (capacity == 0 || buffer == nullptr) {
      return false;
    }
    if (!mutex || xSemaphoreTake(mutex, pdMS_TO_TICKS(50)) != pdTRUE) {
      return false;
    }

    if (count == 0) {
      xSemaphoreGive(mutex);
      return false;
    }

    item = buffer[readPos];
    xSemaphoreGive(mutex);
    return true;
  }

  void clear() {
    if (!mutex || xSemaphoreTake(mutex, pdMS_TO_TICKS(50)) != pdTRUE) {
      return;
    }

    // Reset indexes and counter
    writePos = 0;
    readPos = 0;
    count = 0;

    xSemaphoreGive(mutex);
  }

  size_t size() const { return count; }
  size_t availableSpace() const { return capacity - count; }
  bool empty() const { return count == 0; }
  bool full() const { return count >= capacity; }
  float usage() const { return (float)count / capacity * 100.0f; }
};

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
