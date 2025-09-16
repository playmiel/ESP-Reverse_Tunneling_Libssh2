#pragma once
#include <stdint.h>
#include <stddef.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include "memory_fixes.h"
#include "logger.h"
#include <cstring>

// Structure for pending data (compatible with existing logic)
struct PendingData {
    uint8_t data[1024];  // Static buffer instead of pointer to avoid dynamic allocations
    size_t size;
    size_t offset;
    unsigned long timestamp;
    uint32_t checksum; // NEW: Simple checksum to detect duplication
};

// Generic thread-safe ring buffer
template<typename T>
class RingBuffer {
private:
    T* buffer;
    size_t capacity;
    volatile size_t writePos;
    volatile size_t readPos;
    volatile size_t count;
    SemaphoreHandle_t mutex;
    const char* tag;

public:
    RingBuffer(size_t size, const char* tagName = "RING_BUFFER") : capacity(size), writePos(0), readPos(0), count(0), tag(tagName) {
        buffer = (T*)safeMalloc(sizeof(T) * capacity, tag);
        // Use a real mutex to benefit from priority inheritance and avoid
        // FreeRTOS assertion in vTaskPriorityDisinheritAfterTimeout
        mutex = xSemaphoreCreateMutex();
        LOGF_I("RING", "Created %s: capacity=%d, size=%d bytes", tag, capacity, sizeof(T) * capacity);
    }
    
    ~RingBuffer() {
    // Clear pending data objects if applicable
        clear();
        SAFE_FREE(buffer);
        SAFE_DELETE_SEMAPHORE(mutex);
        LOGF_D("RING", "Destroyed %s", tag);
    }
    
    bool push(const T& item) {
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
    
    bool pop(T& item) {
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
    
    bool peek(T& item) {
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

// Specialized ring buffer for raw byte data
class DataRingBuffer {
private:
    uint8_t* buffer;
    size_t capacity;
    volatile size_t writePos;
    volatile size_t readPos;
    volatile size_t count;
    SemaphoreHandle_t mutex;
    const char* tag;

public:
    DataRingBuffer(size_t size, const char* tagName = "DATA_RING_BUFFER") : capacity(size), writePos(0), readPos(0), count(0), tag(tagName) {
        buffer = (uint8_t*)safeMalloc(capacity, tag);
        // Use a real mutex here as well (not a binary semaphore)
        mutex = xSemaphoreCreateMutex();
        LOGF_I("RING", "Created %s: capacity=%d bytes", tag, capacity);
    }
    
    ~DataRingBuffer() {
        SAFE_FREE(buffer);
        SAFE_DELETE_SEMAPHORE(mutex);
        LOGF_D("RING", "Destroyed %s", tag);
    }
    
    size_t write(const uint8_t* data, size_t len) {
        if (!data || len == 0 || !buffer) return 0;
        
        if (!mutex || xSemaphoreTake(mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
            return 0;
        }
        
        size_t available = capacity - count;
        size_t toWrite = (len > available) ? available : len;
        
    // Optimized write handling wrap-around
        size_t firstChunk = capacity - writePos;
        if (toWrite <= firstChunk) {
            // No wrap-around
            memcpy(buffer + writePos, data, toWrite);
        } else {
            // Wrap-around required
            memcpy(buffer + writePos, data, firstChunk);
            memcpy(buffer, data + firstChunk, toWrite - firstChunk);
        }
        writePos = (writePos + toWrite) % capacity;
    count = count + toWrite; // (une seule fois)
        
        xSemaphoreGive(mutex);
        return toWrite;
    }
    
    size_t read(uint8_t* data, size_t len) {
        if (!data || len == 0 || !buffer) return 0;
        
        if (!mutex || xSemaphoreTake(mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
            return 0;
        }
        
        size_t toRead = (len > count) ? count : len;
        
    // Optimized read handling wrap-around
        size_t firstChunk = capacity - readPos;
        if (toRead <= firstChunk) {
            // No wrap-around
            memcpy(data, buffer + readPos, toRead);
        } else {
            // Wrap-around required
            memcpy(data, buffer + readPos, firstChunk);
            memcpy(data + firstChunk, buffer, toRead - firstChunk);
        }
        readPos = (readPos + toRead) % capacity;
    count = count - toRead; // (une seule fois)
        
        xSemaphoreGive(mutex);
        return toRead;
    }
    
    size_t peek(uint8_t* data, size_t len) {
        if (!data || len == 0 || !buffer) return 0;
        
        if (!mutex || xSemaphoreTake(mutex, pdMS_TO_TICKS(50)) != pdTRUE) {
            return 0;
        }
        
        size_t toRead = (len > count) ? count : len;
        
    // Read without modifying indices
        size_t firstChunk = capacity - readPos;
        if (toRead <= firstChunk) {
            memcpy(data, buffer + readPos, toRead);
        } else {
            memcpy(data, buffer + readPos, firstChunk);
            memcpy(data + firstChunk, buffer, toRead - firstChunk);
        }
        
        xSemaphoreGive(mutex);
        return toRead;
    }
    
    void clear() {
        if (!mutex || xSemaphoreTake(mutex, pdMS_TO_TICKS(50)) != pdTRUE) {
            return;
        }
        
        writePos = 0;
        readPos = 0;
        count = 0;
        
        xSemaphoreGive(mutex);
    }
    
    size_t size() const { return count; }
    size_t available() const { return capacity - count; }
    bool empty() const { return count == 0; }
    bool full() const { return count >= capacity; }
    float usage() const { return (float)count / capacity * 100.0f; }
    
    // Diagnostics
    void printStats() const {
        LOGF_I("RING", "%s: %d/%d bytes (%.1f%%), rPos=%d, wPos=%d", 
               tag, count, capacity, usage(), readPos, writePos);
    }
};

// Template specialization for PendingData
typedef RingBuffer<PendingData> PendingDataRing;
