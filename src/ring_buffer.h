#pragma once
#include "logger.h"
#include "memory_fixes.h"
#include <cstring>
#include <freertos/FreeRTOS.h>
#include <freertos/ringbuf.h>
#include <freertos/semphr.h>
#include <stddef.h>
#include <stdint.h>

// Structure for pending data (compatible with existing logic)
struct PendingData {
  uint8_t data[1024]; // Static buffer instead of pointer to avoid dynamic
                      // allocations
  size_t size;
  size_t offset;
  unsigned long timestamp;
  uint32_t checksum; // Simple checksum for data integrity
};

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
      : capacity(size), writePos(0), readPos(0), count(0), tag(tagName) {
    buffer = (T *)safeMalloc(sizeof(T) * capacity, tag);
    // Use a real mutex to benefit from priority inheritance and avoid
    // FreeRTOS assertion in vTaskPriorityDisinheritAfterTimeout
    mutex = xSemaphoreCreateMutex();
    LOGF_I("RING", "Created %s: capacity=%d, size=%d bytes", tag, capacity,
           sizeof(T) * capacity);
  }

  ~RingBuffer() {
    // Clear pending data objects if applicable
    clear();
    SAFE_FREE(buffer);
    SAFE_DELETE_SEMAPHORE(mutex);
    LOGF_D("RING", "Destroyed %s", tag);
  }

  bool push(const T &item) {
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

// Specialized ring buffer for raw byte data (wraps FreeRTOS ringbuffer)
class DataRingBuffer {
private:
  RingbufHandle_t handle;
  size_t capacity;
  const char *tag;

public:
  DataRingBuffer(size_t size, const char *tagName = "DATA_RING_BUFFER")
      : handle(nullptr), capacity(size), tag(tagName) {
    handle = xRingbufferCreate(capacity, RINGBUF_TYPE_BYTEBUF);
    if (!handle) {
      LOGF_E("RING", "Failed to create %s (capacity=%d bytes)", tag, capacity);
    } else {
      LOGF_I("RING", "Created %s: capacity=%d bytes", tag, capacity);
    }
  }

  ~DataRingBuffer() {
    if (handle) {
      vRingbufferDelete(handle);
      handle = nullptr;
    }
    LOGF_D("RING", "Destroyed %s", tag);
  }

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

  size_t read(uint8_t *data, size_t len) {
    if (!handle || !data || len == 0)
      return 0;

    size_t itemSize = 0;
    uint8_t *item =
        (uint8_t *)xRingbufferReceiveUpTo(handle, &itemSize, 0, len);
    if (!item) {
      return 0;
    }
    size_t toCopy = itemSize > len ? len : itemSize;
    memcpy(data, item, toCopy);
    vRingbufferReturnItem(handle, item);
    return toCopy;
  }

  // Zero-copy acquire/release for flush paths
  size_t acquire(const uint8_t **ptr, size_t maxLen) {
    if (!handle || !ptr || maxLen == 0)
      return 0;
    size_t itemSize = 0;
    const uint8_t *item =
        (const uint8_t *)xRingbufferReceiveUpTo(handle, &itemSize, 0, maxLen);
    *ptr = item;
    return itemSize;
  }

  void release(const void *ptr) {
    if (handle && ptr) {
      vRingbufferReturnItem(handle, (void *)ptr);
    }
  }

  void clear() {
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
    if (!handle)
      return 0;
    size_t freeSpace = xRingbufferGetCurFreeSize(handle);
    return (freeSpace > capacity) ? 0 : (capacity - freeSpace);
  }
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

// Template specialization for PendingData
typedef RingBuffer<PendingData> PendingDataRing;
