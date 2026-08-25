#pragma once
// CLI mode for cloud_redirect - enables the DLL/so to be invoked directly
// for provider management operations (auth, list apps, etc.)
//
// Usage:
//   Windows: cloud_redirect_cli.exe <command> [args...]
//   Linux:   cloud_redirect_cli <command> [args...]
//
// Commands:
// Subcommands: auth-status, authenticate, list-remote-apps, delete-remote-app, list-blobs, delete-blobs
//
// All output is JSON to stdout. Exit code 0 = success, 1 = error.

#include <string>
#include <vector>

namespace CloudRedirectCli {

// Check if arguments indicate CLI mode (first arg is "--cli")
bool IsCliMode(int argc, char** argv);

// Run CLI and return exit code (0 = success)
int RunCli(int argc, char** argv);

// Individual command handlers (return JSON string)
std::string CmdAuthStatus(const std::string& provider);
std::string CmdListRemoteApps(const std::string& provider, const std::string& accountId);
std::string CmdListRemoteAppIds(const std::string& provider, const std::string& accountId);
std::string CmdListRemoteAppFiles(const std::string& provider, const std::string& accountId, const std::string& appId);
std::string CmdDeleteRemoteApp(const std::string& provider, const std::string& accountId, const std::string& appId);
std::string CmdListBlobs(const std::string& provider, const std::string& accountId, const std::string& appId);
std::string CmdDownloadBlob(const std::string& provider, const std::string& accountId,
                            const std::string& appId, const std::string& blobName);
std::string CmdListAllStats(const std::string& provider);
std::string CmdDeleteBlobs(const std::string& provider, const std::string& accountId, const std::string& appId,
                           const std::vector<std::string>& blobNames);
std::string CmdSyncRemoteApp(const std::string& provider, const std::string& accountId, const std::string& appId,
                             const std::string& cloudRoot);
std::string CmdSyncAllRemoteApps(const std::string& provider, const std::string& accountId,
                                 const std::string& cloudRoot);
std::string CmdPruneLocalLegacyMetadata(const std::string& cloudRoot);
std::string CmdPublishFullManifest(const std::string& provider, const std::string& accountId, const std::string& appId,
                                   const std::string& cloudRoot);

} // namespace CloudRedirectCli

// Unified C export for CLI launchers (both Windows and Linux)
extern "C" {
#ifdef _WIN32
    __declspec(dllexport)
#endif
    int CloudRedirect_CliMain(int argc, char** argv);
}
