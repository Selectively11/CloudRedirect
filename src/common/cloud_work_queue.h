#pragma once
#include "cloud_provider.h"
#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace CloudWorkQueue {

struct WorkItem {
    enum Type { Upload, Delete };
    Type        type;
    std::string cloudPath;
    std::vector<uint8_t> data;
    bool        skipIfExists = false;
    bool        bestEffort = false;       // true → does not block commit drains
    int         existsCheckRetries = 0;
    int         transferRetries = 0;
    int         drainRequeues = 0;
    std::chrono::steady_clock::time_point notBefore = std::chrono::steady_clock::time_point{};
};

// User-visible error reporter (MessageBox in production).
using Reporter = std::function<void(const std::string& message)>;

void Init(ICloudProvider* provider);

// Init with custom reporter (nullptr = no-op, tests use this).
void Init(ICloudProvider* provider, Reporter reporter);
void Shutdown();
void SetShuttingDown();
void EnqueueWork(WorkItem item);
void DrainQueue();
bool DrainQueueForApp(uint32_t accountId, uint32_t appId);
bool HasPendingWorkForPrefix(const std::string& prefix);
void ClearFailedWorkForPrefix(const std::string& prefix);

// Report error via installed reporter.
void ShowErrorDialog(const std::string& message);

// Set the base unit (ms) for exponential retry backoff: delay = unit << (retries-1).
// Default 1000ms. Tests set 0 for deterministic, fast retries.
void SetRetryBackoffUnitMs(int unitMs);

// Set the number of background worker threads (clamped to >= 1).
// Default 8. Tests set 1 for deterministic, single-worker repro.
void SetWorkerThreadCount(int count);

} // namespace CloudWorkQueue
