#ifndef MEMORY_FIXES_H
#define MEMORY_FIXES_H

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <esp_system.h>
#include <esp_heap_caps.h>

// Macros pour améliorer la gestion mémoire
#define SAFE_FREE(ptr) do { \
    if ((ptr) != nullptr) { \
        free(ptr); \
        (ptr) = nullptr; \
    } \
} while(0)

#define SAFE_DELETE_SEMAPHORE(sem) do { \
    if ((sem) != NULL) { \
        vSemaphoreDelete(sem); \
        (sem) = NULL; \
    } \
} while(0)

// Fonction pour vérifier l'état de la heap
inline void checkHeapHealth() {
    size_t freeHeap = ESP.getFreeHeap();
    size_t minFreeHeap = ESP.getMinFreeHeap();
    
    if (freeHeap < 50000) { // Moins de 50KB disponible
        Serial.printf("[HEAP_WARNING] Low heap: %d bytes (min: %d)\n", freeHeap, minFreeHeap);
    }
    
    // Vérifier la fragmentation
    size_t largestFreeBlock = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
    if (largestFreeBlock < freeHeap / 2) {
        Serial.printf("[HEAP_WARNING] Fragmentation detected: largest block %d vs free %d\n", 
                     largestFreeBlock, freeHeap);
    }
}

// Allocation sécurisée avec vérification
inline void* safeMalloc(size_t size, const char* tag = "UNKNOWN") {
    checkHeapHealth();
    
    void* ptr = malloc(size);
    if (ptr == nullptr) {
        Serial.printf("[MALLOC_ERROR] Failed to allocate %d bytes for %s\n", size, tag);
        checkHeapHealth();
        return nullptr;
    }
    
    // Initialiser à zéro pour éviter les données aléatoires
    memset(ptr, 0, size);
    
    Serial.printf("[MALLOC_DEBUG] Allocated %d bytes for %s at %p\n", size, tag, ptr);
    return ptr;
}

// Nettoyage périodique de la heap
inline void performHeapMaintenance() {
    // Forcer le compactage de la heap si disponible
    heap_caps_check_integrity_all(true);
    
    // Imprimer l'état de la heap
    size_t total_free = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    size_t total_internal = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    Serial.printf("[HEAP_MAINTENANCE] Free: %d internal, %d total\n", total_internal, total_free);
}

#endif // MEMORY_FIXES_H
