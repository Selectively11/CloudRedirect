#pragma once
// Cooperative main-thread yield.
//
// CompleteBatch and its blob promote run on Steam's BMainLoop thread and block it for
// the whole upload (~43s for a 100-file batch). Starving BMainLoop that long trips
// Steam's frame watchdog at >15s (steamengine.cpp:2838) and a fatal pipe stall
// (pipes.cpp:900) -- a crash on large saves. Native survives because its upload job
// keeps yielding the job fiber; the win32 layer mirrors that with a hook that yields
// the current Steam job (CJob::BYieldIfTimeSlice on g_pJobCur, a no-op unless the job
// held the slice >10ms). Main-thread wait loops call YieldNow between polls.
//
// Constraints:
//   - Re-enters Steam's scheduler; MUST be called holding no CR mutex.
//   - Only valid on BMainLoop; a worker-thread call is a guarded no-op.
//   - Off Steam (Linux, tests) no hook is set and YieldNow does nothing.

#include <functional>
#include <mutex>

namespace CoopYield {

using YieldHook = std::function<void()>;

// Register the platform yield implementation (win32). Pass nullptr to clear.
// Installed at startup and read locklessly thereafter. The hook object is not
// reassigned at runtime; it may instead be atomically disabled via DisableYieldHook
// (e.g. on a yield-primitive fault). Re-registering a non-null hook re-enables it.
void SetYieldHook(YieldHook hook);

// Suppress the hook via an atomic flag rather than clearing it, so it is safe to call
// from inside the hook itself. YieldNow no-ops until a hook is re-registered.
void DisableYieldHook();

// True if a yield hook is installed, i.e. running under Steam. Callers use this to
// pick a yield-poll wait over a hard join.
bool HasYieldHook();

// One cooperative yield (no-op with no hook). Named YieldNow, not Yield, to dodge the
// empty Yield() macro from <windows.h>. Only does anything where the calling thread's
// job coroutine is active (the slot-5 handler level); the win32 hook guards with
// Coroutine_IsActive() and skips otherwise, so calling it elsewhere is a safe no-op.
// Hold no CR mutex across it -- the yield re-enters Steam's scheduler.
void YieldNow();

// Cooperatively wait until done() returns true, keeping BMainLoop responsive. The
// analogue of native CJobFuncs::YieldingWaitForFuncs: yields the job coroutine while
// background work runs instead of hard-blocking in join(). Off Steam it degrades to a
// predicate spin with a short sleep.
//   - MUST run at the active-coroutine handler level and hold no CR mutex.
//   - done() must be cheap and thread-safe (typically an atomic the worker sets).
void PumpUntil(const std::function<bool()>& done);

// Acquire `mtx` without hard-blocking BMainLoop: try_lock() inside the same pump as
// PumpUntil, so while another thread holds it (e.g. a publish thread in a ~20s cloud
// List) the coroutine keeps yielding and the frame watchdog never trips. Off Steam it
// degrades to a try_lock + short-sleep spin. Same contract as PumpUntil (active
// coroutine level, no other CR mutex held). Returns the held lock to the caller.
std::unique_lock<std::mutex> LockCooperatively(std::mutex& mtx);

} // namespace CoopYield
