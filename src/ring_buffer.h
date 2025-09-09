#pragma once
#include <stdint.h>
#include <stddef.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include "memory_fixes.h"
#include "logger.h"

// Structure pour les données en attente (compatible avec l'existant)
struct PendingData {
    uint8_t data[1024];  // Buffer statique au lieu d'un pointeur pour éviter les allocations
    size_t size;
    size_t offset;
    unsigned long timestamp;
    uint32_t checksum; // NOUVEAU: Checksum simple pour détecter les duplications
};

// Ring buffer générique thread-safe
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
        mutex = xSemaphoreCreateBinary();
        if (mutex) {
            xSemaphoreGive(mutex);
        }
        LOGF_I("RING", "Created %s: capacity=%d, size=%d bytes", tag, capacity, sizeof(T) * capacity);
    }
    
    ~RingBuffer() {
        // Nettoyer les données PendingData si c'est le bon type
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
            return false; // Buffer plein
        }
        
        buffer[writePos] = item;
        writePos = (writePos + 1) % capacity;
        count++;
        
        xSemaphoreGive(mutex);
        return true;
    }
    
    bool pop(T& item) {
        if (!mutex || xSemaphoreTake(mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
            return false;
        }
        
        if (count == 0) {
            xSemaphoreGive(mutex);
            return false; // Buffer vide
        }
        
        item = buffer[readPos];
        readPos = (readPos + 1) % capacity;
        count--;
        
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
        
        // Réinitialiser les positions et le compteur
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

// Ring buffer spécialisé pour les données brutes
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
        mutex = xSemaphoreCreateBinary();
        if (mutex) {
            xSemaphoreGive(mutex);
        }
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
        
        // Écriture optimisée en tenant compte du wrap-around
        size_t firstChunk = capacity - writePos;
        if (toWrite <= firstChunk) {
            // Pas de wrap-around
            memcpy(buffer + writePos, data, toWrite);
        } else {
            // Wrap-around nécessaire
            memcpy(buffer + writePos, data, firstChunk);
            memcpy(buffer, data + firstChunk, toWrite - firstChunk);
        }
        
        writePos = (writePos + toWrite) % capacity;
        count += toWrite;
        
        xSemaphoreGive(mutex);
        return toWrite;
    }
    
    size_t read(uint8_t* data, size_t len) {
        if (!data || len == 0 || !buffer) return 0;
        
        if (!mutex || xSemaphoreTake(mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
            return 0;
        }
        
        size_t toRead = (len > count) ? count : len;
        
        // Lecture optimisée en tenant compte du wrap-around
        size_t firstChunk = capacity - readPos;
        if (toRead <= firstChunk) {
            // Pas de wrap-around
            memcpy(data, buffer + readPos, toRead);
        } else {
            // Wrap-around nécessaire
            memcpy(data, buffer + readPos, firstChunk);
            memcpy(data + firstChunk, buffer, toRead - firstChunk);
        }
        
        readPos = (readPos + toRead) % capacity;
        count -= toRead;
        
        xSemaphoreGive(mutex);
        return toRead;
    }
    
    size_t peek(uint8_t* data, size_t len) {
        if (!data || len == 0 || !buffer) return 0;
        
        if (!mutex || xSemaphoreTake(mutex, pdMS_TO_TICKS(50)) != pdTRUE) {
            return 0;
        }
        
        size_t toRead = (len > count) ? count : len;
        
        // Lecture sans modification des pointeurs
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
    
    // Diagnostiques
    void printStats() const {
        LOGF_I("RING", "%s: %d/%d bytes (%.1f%%), rPos=%d, wPos=%d", 
               tag, count, capacity, usage(), readPos, writePos);
    }
};

// Template specialization pour PendingData
typedef RingBuffer<PendingData> PendingDataRing;
