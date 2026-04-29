#ifndef CHANNEL_SLOT_ALLOC_H
#define CHANNEL_SLOT_ALLOC_H

// Header-only utilities for picking a free channel slot.
// Templated on the slot type so the logic can be unit-tested on the host
// without dragging in libssh2 / ESP32 headers; the production caller
// instantiates it with ChannelSlot.

namespace channel_alloc {

// After finalizeClose() flips a slot to active=false, libssh2 may still
// be releasing the underlying channel for a brief moment. Reusing the
// slot inside that window can race with in-flight bytes from the
// previous channel and cause small-chunk byte loss / "Rejecting accepted
// channel after bind failure" (Bug #1 in 2026-04-28 baseline report).
// 50ms is a deliberately small guard: long enough to let the libssh2
// teardown settle, short enough to be invisible under normal traffic.
constexpr unsigned long FINALIZE_COOLDOWN_MS = 50;

// Find the first slot that:
//   - is not active, AND
//   - is either never-finalized (lastFinalizeMs == 0) or past the cooldown.
//
// Returns the slot index, or -1 if no slot is currently allocatable.
//
// SlotT must expose a `bool active` and an `unsigned long lastFinalizeMs`
// field. (ChannelSlot satisfies this; the host test uses a stub.)
template <typename SlotT>
inline int findFreeSlot(const SlotT *slots, int n, unsigned long now,
                        unsigned long cooldown_ms = FINALIZE_COOLDOWN_MS) {
  if (!slots || n <= 0) {
    return -1;
  }
  for (int i = 0; i < n; ++i) {
    if (slots[i].active) {
      continue;
    }
    if (slots[i].lastFinalizeMs != 0 &&
        (now - slots[i].lastFinalizeMs) < cooldown_ms) {
      continue;
    }
    return i;
  }
  return -1;
}

} // namespace channel_alloc

#endif // CHANNEL_SLOT_ALLOC_H
