#include "coop_yield.h"

#include <atomic>
#include <chrono>
#include <thread>

namespace CoopYield {

// g_hook is installed by SetYieldHook at startup. The g_hook object itself is not
// reassigned at runtime; instead g_hookDisabled is flipped to suppress invocation
// (e.g. on a yield-primitive fault), avoiding reassigning/destroying the std::function
// while it may be executing. Acquire/release ordering avoids locking on the hot path.
static YieldHook         g_hook;
static std::atomic<bool> g_hookSet{false};
static std::atomic<bool> g_hookDisabled{false};

void SetYieldHook(YieldHook hook) {
    g_hook = std::move(hook);
    const bool installed = static_cast<bool>(g_hook);
    if (installed) {
        g_hookDisabled.store(false, std::memory_order_release);  // re-register re-enables
    }
    g_hookSet.store(installed, std::memory_order_release);
}

void DisableYieldHook() {
    // Suppress further invocation without touching g_hook (which may be running).
    g_hookDisabled.store(true, std::memory_order_release);
}

bool HasYieldHook() {
    return g_hookSet.load(std::memory_order_acquire);
}

void YieldNow() {
    if (g_hookDisabled.load(std::memory_order_acquire)) return;
    if (g_hookSet.load(std::memory_order_acquire) && g_hook) {
        g_hook();
    }
}

void PumpUntil(const std::function<bool()>& done) {
    // Poll cadence: short enough that BMainLoop stays well under the >15s frame
    // watchdog and feels responsive, long enough not to spin the CPU. The win32
    // yield itself is a no-op unless the job has held its slice >10ms, so this
    // self-throttles toward native's yield cadence.
    constexpr auto kPollInterval = std::chrono::milliseconds(2);
    const bool canYield = g_hookSet.load(std::memory_order_acquire);
    while (!done()) {
        if (canYield) {
            YieldNow();  // guarded inside the hook (skips if coroutine inactive)
        }
        std::this_thread::sleep_for(kPollInterval);
    }
}

std::unique_lock<std::mutex> LockCooperatively(std::mutex& mtx) {
    // Same cadence/rationale as PumpUntil. try_lock() never blocks, so BMainLoop is
    // only ever paused for the yield + 2ms sleep per iteration, well under the >15s
    // watchdog, no matter how long the holding thread keeps the lock.
    constexpr auto kPollInterval = std::chrono::milliseconds(2);
    const bool canYield = g_hookSet.load(std::memory_order_acquire);
    std::unique_lock<std::mutex> lock(mtx, std::defer_lock);
    while (!lock.try_lock()) {
        if (canYield) {
            YieldNow();  // guarded inside the hook (skips if coroutine inactive)
        }
        std::this_thread::sleep_for(kPollInterval);
    }
    return lock;
}

} // namespace CoopYield
