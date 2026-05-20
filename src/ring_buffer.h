#pragma once
#include "logger.h"
#include "memory_fixes.h"
#include "prepend_buffer.h"
#include <cstring>
#include <esp_heap_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/ringbuf.h>
#include <stddef.h>
#include <stdint.h>

// Specialized ring buffer for raw byte data (wraps FreeRTOS ringbuffer).
// Supports writeToFront() to put data back at the HEAD of the buffer,
// preserving FIFO order when a write/send is partial or returns EAGAIN.
//
// All large allocations (ring storage, struct, prepend) are placed in PSRAM
// via heap_caps_malloc() to avoid exhausting the ~320KB internal heap.
// Falls back to regular malloc on boards without PSRAM.
class DataRingBuffer {
private:
  RingbufHandle_t handle = nullptr;
  size_t capacity;
  const char *tag;

  // PSRAM-allocated backing memory for xRingbufferCreateStatic.
  // vRingbufferDelete does NOT free these — we must free them manually.
  uint8_t *ringStorage_ = nullptr;
  StaticRingbuffer_t *ringStruct_ = nullptr;

  // Prepend buffer: holds data that must be read BEFORE the main ring.
  // Used by writeToFront() when a partial write needs to put data back
  // at the front instead of the end (which would break FIFO ordering).
  // Capacity must be >= TransportPump::bufSize_ (default 8192 from
  // ConnectionConfig). The storage is PSRAM-allocated below; PrependBuffer
  // is bound to it via reset() in the constructor.
  static constexpr size_t PREPEND_CAP = 8192;
  uint8_t *prependStorage_ = nullptr;
  PrependBuffer prepend_;

  // Allocate in PSRAM if available, else fall back to regular malloc.
  static void *psramAlloc(size_t size) {
    void *ptr = heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!ptr) {
      ptr = malloc(size); // fallback for non-PSRAM boards
    }
    return ptr;
  }

  static void psramFree(void *ptr) {
    if (ptr) {
      heap_caps_free(ptr);
    }
  }

public:
  DataRingBuffer(size_t size, const char *tagName = "DATA_RING_BUFFER")
      : capacity(size), tag(tagName) {
    // Allocate ring storage and control struct in PSRAM
    ringStorage_ = static_cast<uint8_t *>(psramAlloc(capacity));
    ringStruct_ = static_cast<StaticRingbuffer_t *>(
        psramAlloc(sizeof(StaticRingbuffer_t)));
    if (ringStorage_ && ringStruct_) {
      handle = xRingbufferCreateStatic(capacity, RINGBUF_TYPE_BYTEBUF,
                                       ringStorage_, ringStruct_);
    }

    prependStorage_ = static_cast<uint8_t *>(psramAlloc(PREPEND_CAP));

    if (!handle || !prependStorage_) {
      LOGF_E("RING", "Failed to create %s (capacity=%zu bytes)", tag, capacity);
      if (handle) {
        vRingbufferDelete(handle);
        handle = nullptr;
      }
      psramFree(ringStorage_);
      ringStorage_ = nullptr;
      psramFree(ringStruct_);
      ringStruct_ = nullptr;
      psramFree(prependStorage_);
      prependStorage_ = nullptr;
    } else {
      prepend_.reset(prependStorage_, PREPEND_CAP);
      LOGF_I("RING", "Created %s: capacity=%zu bytes (PSRAM)", tag, capacity);
    }
  }

  ~DataRingBuffer() {
    if (handle) {
      vRingbufferDelete(handle);
      handle = nullptr;
    }
    // xRingbufferCreateStatic does not free storage — we must do it
    psramFree(ringStorage_);
    ringStorage_ = nullptr;
    psramFree(ringStruct_);
    ringStruct_ = nullptr;
    prepend_.reset(nullptr, 0); // unbind before freeing storage
    psramFree(prependStorage_);
    prependStorage_ = nullptr;
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
    return prepend_.writeToFront(data, len);
  }

  // Read data: first drains prepend buffer, then the FreeRTOS ring.
  size_t read(uint8_t *data, size_t len) {
    if (!data || len == 0)
      return 0;

    size_t total = 0;

    // First: drain prepend buffer (data that was put back via writeToFront)
    if (!prepend_.empty()) {
      total += prepend_.read(data, len);
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
    prepend_.clear();
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
    size_t prependRemain = prepend_.pending();
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
