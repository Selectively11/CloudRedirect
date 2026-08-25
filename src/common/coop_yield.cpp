#include "coop_yield.h"

#include <atomic>
#include <chrono>
#include <thread>

namespace CoopYield {

// Disabled via g_hookDisabled rather than clearing g_hook (may be executing).
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
    // 2ms cadence: responsive enough for BMainLoop watchdog, avoids CPU spin.
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
