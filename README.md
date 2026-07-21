# CloudRedirect

""Steam Cloud"" for 'lua' games.

**This is the only official source for CloudRedirect. Any other websites are not operated by me or are otherwise endorsed by this project. At least one of those fake sites is actively distributing malware!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!**

> ****This software is experimental and under active development.**** The underlying techniques are fairly insane. What this software tries to do is nuts to attempt. This software could damage your save files and probably will! It could overwrite your saves, cause weird conflicts, make your saves disappear, make you cry. Back up any saves you care about before using this software.

But it probably won't. It's been very solid for a long time.

>****Do not use this if you do not actively want cloud saves for "lua" games. If all you care about is the Steam Cloud error, disable Steam Cloud in properties for that game.****

## What it does

Valve patched the (sinful) thing SteamTools did to sync saves. Specifically, SteamTools rewrote requests to AppID 760, which is Steam Screenshots. It sent all Steam Cloud requests for non-owned AppIDs there. It did not create prefixes for each individual game, which means that each lua app shared the saves with all others. This can cause saves to conflict if multiple games use the same save file name. This also means that your saves are replicated in the `Steam/Userdata/<steamid>/<appid for lua game>` folder for each lua app.

It also did not support Steam AutoCloud games at all. It would simply show a fake success message for those games.

What _this_ tool does is redirect Steam Cloud requests for games that are injected to Google Drive/OneDrive/a local folder, including AutoCloud games. Everything is native inside the Steam Client, but the actual data is read/written to and from your cloud account. This was much harder to do than just redirecting read/write to an AppID that your account owns, but it was fun to make. It also is less likely to piss off Valve.

This isn't uploading your save files manually or something silly like that. It's the real deal. Steam Cloud, but going to a cloud provider and not Valve.

The tool also has a function to reset the progress of games (useful for auto cloud games that you want to start over in) and a tool to scan SteamTools games for the pollution described above. 

Please treat the cloud 'folder' on your cloud provider the same way you would treat Steam Cloud itself. Don't delete files inside a game's folder in the Cloud or anything like that - you'll just cause a sync error, but stil....

CloudRedirect is good software. It's clever.

## How it works

CloudRedirect for Windows consists of a C++ DLL and a WPF companion app:

1. The companion app patches the SteamTools payload to load the CloudRedirect DLL at startup.
2. The DLL hooks Steam's internal cloud save RPC handlers via ~~vtable interception~~ black magic.
3. When a lua game attempts to read or write cloud save data, the DLL intercepts the calls and redirects it. If the game is owned, the game uses normal Steam Cloud as expected. If a lua is present that only unlocks DLC, the game will use normal Steam Cloud.
4. More dark magic occurs. Saves sync. Bytes flow. This all is visible in the Steam UI and looks identical to normal Steam Cloud functionality.

Same rough idea on Linux, but involving a flatpak application and a library that is loaded on steam startup instead. 
   
## Supported cloud providers

- **Google Drive**
- **OneDrive**
- **Cloudflare R2**
- **S3-Compatible** -- AWS S3, MinIO, Backblaze B2, Wasabi, DigitalOcean Spaces, and any self-hosted S3 server.
- **Local folder / mapped drive** -- by request of literally one user.

With more to come over time. 

## Usage (Windows)

Grab the latest release from the [Releases page](https://github.com/Selectively11/CloudRedirect/releases).

Run the EXE. Pick your mode - STfixer mode for fixes to ST bugs, CloudRedirect mode for the good stuff. In Setup, hit 'Run All Patches'. Go to the Cloud Provider tab, select your provider. If it is a cloud provider, sign in to it.

That's it. Go launch Steam and watch the magic.

## Usage (Linux)

Edit your SLSsteam config, set DisableCloud to No. 


```curl -fsSL headcrab.pages.dev | bash```

Open the CloudRedirect app, sign into a provider.

Edit your SLS config. The games you want to sync must be specified under AdditionalApps in your SLS config. This requirement will go away in the future. 

Now launch Steam and watch your games sync!

## Building from source (Windows)

### Prerequisites

- Visual Studio 2022 (or Build Tools) with the C++ and .NET 8 workloads
- CMake 3.20+

### Build

```bash
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

This builds both the C++ DLL (`build/Release/cloud_redirect.dll`) and publishes the WPF app (`ui/bin/publish/CloudRedirect.exe`). The DLL is automatically embedded into the executable.

Or don't build it? Building Windows apps is pain.

## Building from source (Linux)

Oooooh boy. Yeah. Have fun. 

You need to build against glibc 2.31 or older. Ubuntu 20.04 would work, if you dislike yourself. There's also an ancient version of Fedora that fits the bill. Or Debian 11. Distrobox is the way, here. Don't even bother trying to build under whatever distro you daily, you'll wind up fighting it for no reason. Distrobox exists for a reason. 

If you are building under Ubuntu 20.04, GCC 12 is needed along with the 32-bit multilib stuff. System cmake is ancient garbage, you'll have to update it.

Then specify -DLINUX_32BIT=ON and wham bam.

Isn't building for weird distros _fun?_
