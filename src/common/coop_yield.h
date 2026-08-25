#pragma once
// Cooperative main-thread yield. Prevents BMainLoop starvation (>15s watchdog).
// Re-enters Steam's scheduler; MUST be called holding no CR mutex.

#include <functional>
#include <mutex>

namespace CoopYield {

using YieldHook = std::function<void()>;

// Disabled atomically via DisableYieldHook; re-register re-enables.
void SetYieldHook(YieldHook hook);

// Suppress the hook via an atomic flag rather than clearing it, so it is safe to call
// from inside the hook itself. YieldNow no-ops until a hook is re-registered.
void DisableYieldHook();

// True if a yield hook is installed, i.e. running under Steam. Callers use this to
// pick a yield-poll wait over a hard join.
bool HasYieldHook();

// One cooperative yield (safe no-op without hook or outside coroutine).
void YieldNow();

// Wait cooperatively until done() returns true. No CR mutex held.
void PumpUntil(const std::function<bool()>& done);

// Acquire mtx cooperatively (try_lock + yield loop). No CR mutex held.
std::unique_lock<std::mutex> LockCooperatively(std::mutex& mtx);

} // namespace CoopYield
