#include "metadata_sync.h"

namespace MetadataSync {

std::atomic<bool> steamToolsPresent{false};
std::atomic<bool> syncLuas{false};
// Default OFF: WIP opt-in features; the user enables them.
std::atomic<bool> syncAchievements{false};
std::atomic<bool> syncPlaytime{false};
// Default OFF: experimental opt-in feature.
std::atomic<bool> schemaFetch{false};
// Default OFF: gate metadata features to ST clients (unsupported WIP override).
std::atomic<bool> overrideNonStGate{false};

}
