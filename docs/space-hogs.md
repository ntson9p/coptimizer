# What eats the C: drive on Windows

COptimizer's rule catalog is built from this list: what fills a Windows system drive, where it lives, how big it gets, and the safe way to reclaim it.

**Tiers** (the app shows one on every finding):

- **Safe**: regenerable data (caches, temp files, logs, crash dumps). Cleaning only costs some re-download or rebuild time.
- **Moderate**: cleaning removes an ability (hibernation, going back to the previous Windows, uninstalling updates, restore points). The app explains the trade-off and needs an explicit acknowledgement.
- **Manual**: personal data, or something only its own app or Windows should remove. The app reports it and opens the folder; it never deletes it.

**Path shorthands**: `%LOCALAPPDATA%` = `C:\Users\<name>\AppData\Local`, `%APPDATA%` = `C:\Users\<name>\AppData\Roaming`, `%USERPROFILE%` = `C:\Users\<name>`, `%PROGRAMDATA%` = `C:\ProgramData`. Sizes are typical ranges seen on real PCs, not limits.

## 1. The most severe offenders

Ranked by typical size × how often it shows up.

| # | Offender | Typical size | Who has it | Tier |
|---|---|---|---|---|
| 1 | Personal files: Downloads, Desktop, Videos, Documents (installers, ISOs, archives, recordings) | 10–200+ GB | Almost everyone | Manual |
| 2 | Games installed on C: | 20–150 GB per game | Gamers | Manual |
| 3 | Virtual disks that grow but never shrink: WSL, Docker, VMs, Android emulators | 10–100+ GB | Developers, emulator gamers | Moderate |
| 4 | Local AI models: Ollama, Hugging Face, LM Studio, Stable Diffusion / ComfyUI | 10–300 GB | Growing fast | Manual |
| 5 | Previous Windows installation and upgrade leftovers (`Windows.old`, `$Windows.~BT`, `$GetCurrent`) | 5–30 GB | After each feature update | Moderate |
| 6 | Hibernation file + page file | 0.5–1.5 × RAM together | Every PC | Moderate |
| 7 | Developer caches and SDKs: npm, Gradle, Android SDK, NuGet, pip/conda, Playwright… | 5–50 GB | Developers | Safe |
| 8 | Local copies of cloud data: Outlook `.ost`, OneDrive "Always keep on this device", Google Drive cache, iPhone backups | 10–100+ GB | Office users, iPhone owners | Manual |
| 9 | Windows Update leftovers: superseded components, download cache, Delivery Optimization | 2–15 GB | Every PC | Safe |
| 10 | System Restore points (shadow copies) | up to the cap, often 5–20 GB | When System Protection is on | Moderate |
| 11 | Creative-app caches and recordings: Premiere / After Effects / Resolve / CapCut caches, Lightroom previews, game and screen captures | 10–100+ GB | Creators, streamers | Safe / Manual |
| 12 | Crash dumps and runaway logs: `MEMORY.DMP`, `LiveKernelReports`, Windows Error Reporting, `CBS.log`, IIS logs | 1–50 GB | Occasional, sometimes extreme | Safe |
| 13 | Browser and chat-app caches: Chrome, Edge, Cốc Cốc, Discord, Teams, Zalo, Telegram | 1–20 GB | Everyone | Safe / Manual |
| 14 | Temp folders and the Recycle Bin | 1–20 GB | Everyone | Safe |
| 15 | Copilot+ PCs: Recall snapshots | up to its cap (25–150 GB) | Copilot+ PCs with Recall on | Moderate |
| 16 | Bloated Windows Search index | 1–50 GB | Occasional | Moderate |
| 17 | GPU driver leftovers: extracted installers, old driver packages, shader caches | 1–10 GB | PCs with NVIDIA / AMD GPUs | Safe / Moderate |
| 18 | Reserved storage (held back by Windows for updates) | ~7 GB | Most Windows 10/11 installs | Manual (by design) |

## 2. Full catalog

### 2.1 Windows system files

| What | Where | Typical size | How to reclaim | Tier |
|---|---|---|---|---|
| Hibernation file | `C:\hiberfil.sys` | 40% of RAM | `powercfg /h /type reduced` (about 20% of RAM; keeps Fast Startup, drops Hibernate) or `powercfg /h off` (also disables Fast Startup) | Moderate |
| Page file | `C:\pagefile.sys` | 2–16 GB | Move most of it to another internal drive (System → Advanced → Virtual memory); keep a small one on C: if you want crash dumps. Never disable it completely. Needs a reboot | Moderate (guided) |
| Restore points / shadow copies | `C:\System Volume Information` (managed by VSS) | up to the "Max usage" cap, often 3–10% of the drive | Delete all but the newest (Disk Cleanup → More Options); lower the cap: `vssadmin resize shadowstorage /for=C: /on=C: /maxsize=5%` | Moderate |
| Component store | `C:\Windows\WinSxS` | 6–15 GB as Explorer shows it; much of it is hard links shared with System32 | `DISM /Online /Cleanup-Image /StartComponentCleanup`; adding `/ResetBase` frees more but makes installed updates permanent. Never delete files by hand | Safe / Moderate |
| Windows Installer cache | `C:\Windows\Installer` | 1–20 GB | Don't delete: needed to repair, update and uninstall programs. Uninstalling unused programs shrinks it | Manual |
| Driver store | `C:\Windows\System32\DriverStore\FileRepository` | 2–10 GB | Disk Cleanup "Device driver packages"; advanced: `pnputil /enum-drivers`, then delete old packages that aren't in use | Moderate |
| Reserved storage | hidden | ~7 GB | Keep it (Microsoft's recommendation); the app only reports it (`DISM /Online /Get-ReservedStorageState`) | Manual |
| Uncompressed OS files | `C:\Windows` | saves 1.5–3 GB | Compact OS: `compact /CompactOS:always` (reversible, small CPU cost) | Moderate |
| Search index | `C:\ProgramData\Microsoft\Search\Data\Applications\Windows` | normally < 1 GB; bloated 5–50 GB | Rebuild it (Indexing Options → Advanced → Rebuild); exclude huge folders and mailboxes | Moderate |
| System memory dumps | `C:\Windows\MEMORY.DMP`, `C:\Windows\Minidump` | up to RAM size | Delete once you no longer need them to diagnose a crash | Safe |
| Live kernel reports | `C:\Windows\LiveKernelReports` | 0.5–20 GB | GPU and driver timeouts write large dumps here; delete the `.dmp` files | Safe |
| Windows Error Reporting | `%PROGRAMDATA%\Microsoft\Windows\WER\{ReportArchive,ReportQueue,Temp}`, `%LOCALAPPDATA%\Microsoft\Windows\WER` | 0.1–10 GB | Delete | Safe |
| App crash dumps | `%LOCALAPPDATA%\CrashDumps` | 0.1–20 GB | Apps that crash in a loop leave full dumps; delete | Safe |
| Servicing and setup logs | `C:\Windows\Logs\CBS` (`CBS.log`, `CbsPersist_*.cab`), `C:\Windows\Logs\DISM`, `C:\Windows\Panther` | 0.1–20 GB when CBS logs run away | Delete old `.log` and `.cab` files | Safe |
| Diagnostic traces | `%PROGRAMDATA%\Microsoft\Diagnosis`, `C:\Windows\System32\LogFiles\WMI` | 0.1–5 GB | Settings → Privacy & security → Diagnostics & feedback → Delete diagnostic data; Disk Cleanup | Safe |
| Web server logs | `C:\inetpub\logs\LogFiles` | 0–100 GB | IIS never rotates them by default; delete old logs and set up rotation | Safe |
| System temp | `C:\Windows\Temp`, `C:\Windows\SystemTemp` | 0.1–10 GB | Delete files older than a day | Safe |
| Thumbnail and icon caches | `%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db`, `iconcache_*.db` | 0.1–3 GB | Disk Cleanup "Thumbnails"; rebuilt automatically | Safe |
| DirectX shader cache | `%LOCALAPPDATA%\D3DSCache` | 0.1–5 GB | Delete; rebuilt on demand (first launch of a game is slower) | Safe |
| Stuck print jobs | `C:\Windows\System32\spool\PRINTERS` | usually 0, sometimes GBs | Stop the Print Spooler, delete, start it | Safe |
| Recall snapshots (Copilot+ PCs) | `%LOCALAPPDATA%\CoreAIPlatform.00\UKP` | up to its storage cap (default depends on disk size, 25–150 GB) | Settings → Privacy & security → Recall & snapshots: lower the cap or delete snapshots | Moderate |

### 2.2 Windows update and upgrade leftovers

| What | Where | Typical size | How to reclaim | Tier |
|---|---|---|---|---|
| Previous Windows installation | `C:\Windows.old` (also `Windows.old(1)`…) | 10–30 GB | Kept 10 days for rollback, then normally removed automatically. Remove early with Disk Cleanup "Previous Windows installation(s)" or Settings → System → Storage → Temporary files; deleting by hand fails on TrustedInstaller permissions | Moderate (no rollback) |
| Upgrade staging | `C:\$Windows.~BT`, `C:\$Windows.~WS`, `C:\$WINDOWS.~Q`, `C:\ESD` | 3–10 GB | Disk Cleanup "Temporary Windows installation files"; only when no upgrade is in progress | Moderate |
| Update Assistant leftovers | `C:\$GetCurrent`, `C:\Windows10Upgrade` | 1–5 GB | Delete `$GetCurrent` when not upgrading; uninstall "Windows 10 Update Assistant" from Apps | Safe |
| Reset and recovery leftovers | `C:\$SysReset`, `C:\$WinREAgent` | 0.1–2 GB | Delete `$SysReset`; leave `$WinREAgent` while a recovery-environment update is pending | Safe / Moderate |
| Windows Update download cache | `C:\Windows\SoftwareDistribution\Download` | 0.1–10 GB | Disk Cleanup "Windows Update Cleanup"; or stop `wuauserv` and `bits`, delete, start them again | Safe |
| Delivery Optimization cache | `C:\Windows\SoftwareDistribution\DeliveryOptimization` or `C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization` | 0.5–10 GB | `Delete-DeliveryOptimizationCache -Force` (PowerShell) | Safe |
| Upgrade logs | `C:\Windows\Panther`, `C:\$Windows.~BT\Sources\Panther` | 0.1–1 GB | Disk Cleanup "Windows upgrade log files" | Safe |
| ESD installation files | used by "Reset this PC" | 3–5 GB | Disk Cleanup "Windows ESD installation files"; afterwards a reset needs installation media or a cloud download | Moderate |

### 2.3 Driver and hardware-vendor leftovers

| What | Where | Typical size | How to reclaim | Tier |
|---|---|---|---|---|
| NVIDIA installer files | `C:\NVIDIA`, `%PROGRAMDATA%\NVIDIA Corporation\Downloader` | 0.5–5 GB | Each driver update downloads and extracts about 1 GB; delete | Safe |
| AMD / Intel installer files | `C:\AMD`, `C:\Intel` | 0.5–3 GB | Extracted driver packages; delete | Safe |
| GPU shader caches | `%LOCALAPPDATA%\NVIDIA\{DXCache,GLCache}`, `%PROGRAMDATA%\NVIDIA Corporation\NV_Cache`, `%LOCALAPPDATA%\AMD\{DxCache,DxcCache,VkCache,GLCache}`, `%LOCALAPPDATA%\Intel\ShaderCache` | 0.1–10 GB | Delete; rebuilt as games run (brief stutter) | Safe |
| Old driver versions | Driver store (see 2.1) | about 1 GB per old GPU driver | Disk Cleanup "Device driver packages" or `pnputil` | Moderate |
| PC-maker preload folders | `C:\SWSetup` (HP), `C:\Drivers`, `C:\Dell` | 1–10 GB | Driver and recovery copies from the manufacturer; delete only after checking the drivers are installed | Manual |

### 2.4 Virtual disks and emulators

These grow as you use them and don't shrink on their own when you delete files inside them.

| What | Where | Typical size | How to reclaim | Tier |
|---|---|---|---|---|
| WSL distributions | `%LOCALAPPDATA%\wsl\{GUID}\ext4.vhdx`; Store installs: `%LOCALAPPDATA%\Packages\CanonicalGroupLimited.*\LocalState\ext4.vhdx` | 2–100 GB | Clean inside Linux first (`apt clean`, `~/.cache`); `wsl --manage <distro> --set-sparse true` gives freed space back automatically; compact after `wsl --shutdown`; move with `wsl --manage <distro> --move D:\WSL\<distro>` | Moderate |
| Docker Desktop | `%LOCALAPPDATA%\Docker\wsl\disk\docker_data.vhdx` (older: `%LOCALAPPDATA%\Docker\wsl\data\ext4.vhdx`) | 5–150 GB | `docker system df`; `docker builder prune`; `docker image prune -a`; volumes only if you're sure; move with Settings → Resources → Advanced → Disk image location | Moderate |
| Hyper-V VMs | `C:\ProgramData\Microsoft\Windows\Virtual Hard Disks` | 20–100 GB per VM | Delete unused VMs and checkpoints in Hyper-V Manager; move the rest | Manual |
| VirtualBox / VMware VMs | `%USERPROFILE%\VirtualBox VMs`, `%USERPROFILE%\Documents\Virtual Machines` | 20–100 GB per VM | Delete old snapshots and VMs inside the app | Manual |
| Android Studio emulators | `%USERPROFILE%\.android\avd` | 2–10 GB per device | Delete unused devices in Device Manager | Manual |
| Android game emulators | BlueStacks `C:\ProgramData\BlueStacks_nxt`, LDPlayer `<install folder>\vms`, NoxPlayer, MEmu | 5–50 GB | Each instance is a full Android disk; delete unused instances in the emulator's multi-instance manager | Manual |
| Windows Subsystem for Android (discontinued March 2025) | `%LOCALAPPDATA%\Packages\MicrosoftCorporationII.WindowsSubsystemForAndroid_8wekyb3d8bbwe` | 2–20 GB | Uninstall | Manual |

### 2.5 Developer tools

| What | Where | Typical size | How to reclaim | Tier |
|---|---|---|---|---|
| npm cache | `%LOCALAPPDATA%\npm-cache` | 1–20 GB | `npm cache clean --force`; relocate with `npm config set cache D:\npm-cache` | Safe |
| pnpm | metadata cache `%LOCALAPPDATA%\pnpm-cache`; package store `%LOCALAPPDATA%\pnpm\store`, or `<drive>:\.pnpm-store` on the drive that holds your projects | 1–30 GB | Store: `pnpm store prune`; metadata cache: delete the folder | Safe |
| Yarn / Bun | `%LOCALAPPDATA%\Yarn\Cache`, `%LOCALAPPDATA%\Yarn\Berry\cache`, `%USERPROFILE%\.bun\install\cache` | 0.5–10 GB | `yarn cache clean`, `bun pm cache rm` | Safe |
| Node versions | `%APPDATA%\nvm` (nvm-windows), Volta, fnm | 0.1–0.2 GB per version | `nvm list`, `nvm uninstall <version>` | Safe |
| `node_modules` in projects on C: | anywhere under your projects | 0.2–2 GB each | Reinstallable; the app lists them with last-modified dates | Manual |
| Browser-testing tools | `%LOCALAPPDATA%\ms-playwright`, `%USERPROFILE%\.cache\puppeteer`, `%LOCALAPPDATA%\Cypress\Cache` | 0.5–5 GB | `npx playwright uninstall --all`, `npx cypress cache prune`, or delete | Safe |
| Electron and native-build caches | `%LOCALAPPDATA%\electron\Cache`, `%LOCALAPPDATA%\electron-builder\Cache`, `%LOCALAPPDATA%\node-gyp\Cache` | 0.2–3 GB | Delete | Safe |
| pip / uv | `%LOCALAPPDATA%\pip\Cache`, `%LOCALAPPDATA%\uv\cache` | 0.5–20 GB | `pip cache purge`, `uv cache clean` | Safe |
| Conda | `<conda folder>\pkgs`, `<conda folder>\envs` | 2–30 GB | `conda clean --all`; remove unused environments | Safe / Manual |
| Poetry, pyenv-win, virtual environments | `%LOCALAPPDATA%\pypoetry\Cache`, `%USERPROFILE%\.pyenv\pyenv-win\versions`, `.venv` folders in projects | 0.5–10 GB | `poetry cache clear --all pypi`; remove unused Python versions and venvs | Safe / Manual |
| NuGet | `%USERPROFILE%\.nuget\packages`, `%LOCALAPPDATA%\NuGet\v3-cache` | 1–20 GB | `dotnet nuget locals all --clear` | Safe |
| Visual Studio download cache | `C:\ProgramData\Microsoft\VisualStudio\Packages` | 2–20 GB | Turn off the installer's download cache (`--nocache`, or the `KeepDownloadedPayloads` policy) | Moderate |
| MSI / Burn package cache | `C:\ProgramData\Package Cache` | 1–10 GB | Don't delete: needed to repair and uninstall Visual Studio, .NET and VC++ runtimes | Manual |
| Visual Studio symbols and caches | `%LOCALAPPDATA%\Temp\SymbolCache`, `%LOCALAPPDATA%\Microsoft\VisualStudio\<version>\ComponentModelCache` | 0.5–10 GB | Delete with Visual Studio closed | Safe |
| Old SDKs and toolkits | `C:\Program Files\dotnet\sdk`, `C:\Program Files (x86)\Windows Kits`, `C:\Program Files\NVIDIA GPU Computing Toolkit`, JDKs | 0.3–10 GB each | Updates install side by side; uninstall old versions from Apps | Moderate |
| Gradle | `%USERPROFILE%\.gradle\caches`, `%USERPROFILE%\.gradle\wrapper\dists` | 2–30 GB | `gradle --stop`, then delete the caches and old wrapper versions | Safe |
| Maven | `%USERPROFILE%\.m2\repository` | 1–10 GB | Delete (downloads again on demand) | Safe |
| Android SDK | `%LOCALAPPDATA%\Android\Sdk` (system-images, platforms, ndk, build-tools) | 5–50 GB | Remove old platforms, images and NDKs in SDK Manager | Manual |
| Rust | `%USERPROFILE%\.cargo\registry`, `%USERPROFILE%\.rustup\toolchains`, `target` folders in projects | 1–50 GB | `cargo clean` per project; `rustup toolchain uninstall`; delete the registry cache | Safe / Manual |
| Go | `%LOCALAPPDATA%\go-build`, `%USERPROFILE%\go\pkg\mod` | 1–10 GB | `go clean -cache`, `go clean -modcache` | Safe |
| Composer, Dart / Flutter, Deno | `%LOCALAPPDATA%\Composer`, `%LOCALAPPDATA%\Pub\Cache`, `%LOCALAPPDATA%\deno` | 0.2–5 GB | `composer clear-cache`, `flutter pub cache clean`, `deno clean` | Safe |
| Windows package managers | `%USERPROFILE%\scoop\cache` and old app versions, `%TEMP%\chocolatey`, `C:\ProgramData\chocolatey\lib-bkp`, `%LOCALAPPDATA%\Temp\WinGet` | 0.5–10 GB | `scoop cleanup *`, `scoop cache rm *`; delete the temp folders | Safe |
| Editors | VS Code: `%APPDATA%\Code\{Cache,CachedData,CachedExtensionVSIXs,logs}`, `%APPDATA%\Code\User\workspaceStorage`, `%USERPROFILE%\.vscode\extensions`; the same layout for Cursor, Windsurf and Code - Insiders | 0.5–10 GB | Delete caches with the editor closed; prune old workspaceStorage entries | Safe |
| JetBrains IDEs | `%LOCALAPPDATA%\JetBrains\<Product><version>`, `%APPDATA%\JetBrains` | 1–10 GB per version | Caches of older IDE versions stay after upgrades; delete folders for versions no longer installed | Safe |
| Game engines | Unreal `%LOCALAPPDATA%\UnrealEngine\Common\DerivedDataCache`; Unity `%LOCALAPPDATA%\Unity\cache`, `%APPDATA%\Unity\Asset Store-5.x` | 5–100 GB | Delete the derived-data cache (rebuilt, slowly) | Safe |
| Local Kubernetes | `%USERPROFILE%\.minikube`, kind clusters inside Docker | 2–10 GB | `minikube delete` | Moderate |

### 2.6 Local AI and machine learning

| What | Where | Typical size | How to reclaim | Tier |
|---|---|---|---|---|
| Ollama models | `%USERPROFILE%\.ollama\models` | 4–200 GB | `ollama list`, `ollama rm <model>`; relocate with the `OLLAMA_MODELS` variable | Manual |
| Hugging Face cache | `%USERPROFILE%\.cache\huggingface\hub` | 5–300 GB | Every model revision downloaded by transformers / diffusers stays; `huggingface-cli scan-cache` and `delete-cache` (newer CLI: `hf cache …`); relocate with `HF_HOME` | Manual |
| LM Studio | `%USERPROFILE%\.lmstudio\models` (older: `%USERPROFILE%\.cache\lm-studio\models`) | 4–200 GB | Delete models in the app; change the models folder | Manual |
| Stable Diffusion / ComfyUI / Forge | `<install folder>\models` | 10–200 GB | Checkpoints and LoRAs; delete unused ones | Manual |
| PyTorch hub and big wheels | `%USERPROFILE%\.cache\torch`, CUDA wheels inside the pip / uv caches | 1–20 GB | Delete; clean the pip / uv caches | Safe |
| Chrome on-device AI (Gemini Nano) | `%LOCALAPPDATA%\Google\Chrome\User Data\OptGuideOnDeviceModel` | 2–4 GB | Delete; Chrome downloads it again unless on-device AI is turned off (Chrome settings, or the `GenAILocalFoundationalModelSettings` policy) | Safe |

More apps ship on-device models every year; the app's "unrecognized big folder" check (section 2.12) catches new ones.

### 2.7 Browsers

| What | Where | Typical size | How to reclaim | Tier |
|---|---|---|---|---|
| Chromium-based browsers (Chrome, Edge, Brave, Opera, Vivaldi, Cốc Cốc) | In each profile: `Cache`, `Code Cache`, `GPUCache`, `Service Worker\CacheStorage`, `Service Worker\ScriptCache`; in `User Data`: `ShaderCache`, `GrShaderCache`, `GraphiteDawnCache`. Roots: Chrome `%LOCALAPPDATA%\Google\Chrome\User Data`, Edge `%LOCALAPPDATA%\Microsoft\Edge\User Data`, Brave `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data`, Vivaldi `%LOCALAPPDATA%\Vivaldi\User Data`, Cốc Cốc `%LOCALAPPDATA%\CocCoc\Browser\User Data`, Opera `%APPDATA%\Opera Software\Opera Stable` and `%LOCALAPPDATA%\Opera Software\Opera Stable` | 0.5–5 GB per profile; Service Worker caches can reach many GB | Delete only these cache folders, with the browser closed. Never cookies, history, passwords, Local Storage or IndexedDB (they hold logins and offline data) | Safe |
| Firefox | `%LOCALAPPDATA%\Mozilla\Firefox\Profiles\<profile>\cache2` | 0.3–2 GB | Delete `cache2` with Firefox closed | Safe |
| Site data of heavy web apps | IndexedDB and File System folders in the profile | 0.5–10 GB | Clear per site in the browser's settings | Manual |
| Unused browser profiles | `User Data\Profile N` | 0.5–5 GB each | Remove the profile in the browser | Manual |

### 2.8 Mail, chat and cloud sync

| What | Where | Typical size | How to reclaim | Tier |
|---|---|---|---|---|
| Outlook (classic) offline mailbox | `%LOCALAPPDATA%\Microsoft\Outlook\*.ost`; archives `Documents\Outlook Files\*.pst` | 2–50 GB | Lower "Mail to keep offline" in the account settings; keep PST archives on another drive | Manual |
| Microsoft Teams | new Teams `%LOCALAPPDATA%\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams`; classic `%APPDATA%\Microsoft\Teams` | 0.5–5 GB | Clear the cache with Teams closed (Settings → Apps → Teams → Reset also works) | Safe |
| Electron chat apps (Slack, Discord, Zalo, Messenger, Skype) | `%APPDATA%\<app>\{Cache,Code Cache,GPUCache,DawnCache}`, e.g. `%APPDATA%\ZaloData\Cache` | 0.2–5 GB | Delete only these cache folders, with the app closed. The rest of the folder holds chat data and logins | Safe |
| Chat media and history | Zalo `%APPDATA%\ZaloData`; Telegram `%USERPROFILE%\Downloads\Telegram Desktop` and `%APPDATA%\Telegram Desktop\tdata`; WhatsApp `%LOCALAPPDATA%\Packages\5319275A.WhatsAppDesktop_cv1g1gvanyjgm\LocalState` | 1–50 GB | Use each app's own storage manager (Telegram: Settings → Advanced → Manage local storage, which also sets a size limit) | Manual |
| OneDrive | `%USERPROFILE%\OneDrive*`: files set to "Always keep on this device" | 0–1000 GB | Right-click → "Free up space" (keeps them online-only) | Manual |
| Google Drive for desktop | `%LOCALAPPDATA%\Google\DriveFS` | 1–20 GB | Move the local cache folder in Drive's settings; mirrored folders take their full size | Manual |
| Dropbox / iCloud | `%USERPROFILE%\Dropbox`, `%USERPROFILE%\iCloudDrive`, iCloud Photos | varies | Make folders online-only | Manual |
| iPhone / iPad backups | `%APPDATA%\Apple Computer\MobileSync\Backup`; Microsoft Store iTunes or Apple Devices: `%USERPROFILE%\Apple\MobileSync\Backup` | 5–200 GB | Delete old backups in Apple Devices or iTunes → Manage Backups | Manual |
| Office file cache | `%LOCALAPPDATA%\Microsoft\Office\16.0\OfficeFileCache` | 0.1–5 GB | Delete with Office closed | Safe |

### 2.9 Media and creative apps

| What | Where | Typical size | How to reclaim | Tier |
|---|---|---|---|---|
| Adobe Premiere / After Effects media cache | `%APPDATA%\Adobe\Common\Media Cache Files`, `%APPDATA%\Adobe\Common\Media Cache` | 5–100 GB | Preferences → Media Cache → Delete; turn on automatic cleanup; move it to another drive | Safe |
| Lightroom Classic previews | `Pictures\Lightroom\*Previews.lrdata` | 5–100 GB | Library → Previews → Discard 1:1 Previews; set automatic discard | Manual |
| Photoshop scratch files | `%LOCALAPPDATA%\Temp\Photoshop Temp*` | 1–50 GB after crashes | Delete with Photoshop closed | Safe |
| DaVinci Resolve cache | `CacheClip` folder under the media storage location | 5–100 GB | Playback → Delete Render Cache; put the cache on another drive | Safe |
| CapCut | `%LOCALAPPDATA%\CapCut\User Data\Cache` | 1–30 GB | Clear the cache in CapCut's settings | Safe |
| Screen and game recordings | `%USERPROFILE%\Videos\Captures` (Game Bar), `%USERPROFILE%\Videos` (OBS, NVIDIA) | 5–200 GB | The app lists the biggest videos; you decide | Manual |
| Offline music and video | Spotify `%LOCALAPPDATA%\Spotify\Storage` (Store version: `%LOCALAPPDATA%\Packages\SpotifyAB.SpotifyMusic_zpdnekdrzrea0\LocalCache\Spotify\Data`), Netflix / Disney+ app downloads, `Music\iTunes` | 1–50 GB | Clear the cache or move offline storage in each app | Manual |

### 2.10 Games

| What | Where | Typical size | How to reclaim | Tier |
|---|---|---|---|---|
| Installed games | Steam `C:\Program Files (x86)\Steam\steamapps\common`; Epic `C:\Program Files\Epic Games`; Xbox app `C:\XboxGames`; Battle.net, EA app, Ubisoft Connect, Riot, Garena | 20–150 GB per game | Move libraries with the launcher's own tool (Steam → Settings → Storage → Move) | Manual |
| Steam leftovers | `steamapps\shadercache`, `steamapps\downloading`, `steamapps\temp`, `Steam\dumps` | 0.5–20 GB | Delete the shader cache (rebuilt) and stale downloads | Safe |
| Epic Vault cache | `C:\Program Files (x86)\Epic Games\Launcher\VaultCache` | 1–50 GB | Unreal Marketplace downloads; delete, or move it in the launcher's settings | Safe |
| Game crash dumps and replays | `Documents\My Games`, `%LOCALAPPDATA%\<Game>\Saved\Crashes` | 0.1–10 GB | The app reports them | Manual |

### 2.11 Personal files

| What | Where | Typical size | How to reclaim | Tier |
|---|---|---|---|---|
| Downloads | `%USERPROFILE%\Downloads` | 1–200 GB | Old installers (`.exe`, `.msi`), ISOs and archives pile up; the app lists them by type and age | Manual |
| Desktop, Documents, Pictures, Videos, Music | user folders | varies | The app lists the biggest files and folders; move whole folders to another drive (folder Properties → Location) | Manual |
| Duplicate files | anywhere | varies | The same photos and videos copied many times; the app finds duplicates among big files | Manual |
| Old user profiles | `C:\Users\<old account>` | 1–50 GB | Remove in System Properties → Advanced → User Profiles | Manual |
| Projects and Git repositories on C: | `%USERPROFILE%\source\repos`, `Documents\GitHub`, … | varies | `git gc`; move projects to another drive | Manual |
| Recycle Bin | `C:\$Recycle.Bin` | up to its size limit | Deleted files still use space until the bin is emptied | Safe |
| User temp | `%LOCALAPPDATA%\Temp` | 0.5–30 GB | Installers and apps forget to clean up; delete files older than a day, skip files in use | Safe |

### 2.12 Everything else

| What | Where | Typical size | How to reclaim | Tier |
|---|---|---|---|---|
| Antivirus quarantine and logs | vendor folders under `%PROGRAMDATA%`; `%PROGRAMDATA%\Microsoft\Windows Defender\Scans\History` | 0.1–5 GB | Clear inside the antivirus app | Manual |
| Runaway log files | any `*.log` over ~500 MB under AppData or ProgramData | 0.5–50 GB | A misbehaving app logging forever; delete with the app closed | Safe (reported first) |
| Leftovers of uninstalled apps | `%LOCALAPPDATA%\<app>`, `%APPDATA%\<app>`, `%PROGRAMDATA%\<app>` | 0.1–10 GB | The app flags folders that match no installed program; you decide | Manual |
| Unrecognized big folders | anywhere | varies | Anything ≥ 1 GB that matches no rule is shown, with a "looks like a cache" hint when its name suggests one | Manual |

## 3. Never delete these by hand

- `C:\Windows\WinSxS`: use DISM.
- `C:\Windows\Installer` (including `$PatchCache$`): breaks repair, updates and uninstall of programs.
- `C:\Windows\System32\DriverStore`: use Disk Cleanup or `pnputil`.
- `C:\ProgramData\Package Cache`: breaks repair and uninstall of Visual Studio, .NET and VC++ runtimes.
- `C:\System Volume Information`: use System Protection or `vssadmin`.
- `pagefile.sys`, `hiberfil.sys`: change them through Windows settings or `powercfg`.
- `C:\Program Files`, `C:\Program Files\WindowsApps`: uninstall instead.
- An app's whole `AppData\Local` or `AppData\Roaming` folder: it holds settings, logins, chat history and game saves.
- `C:\Windows\Prefetch`: tiny and managed by Windows; clearing it only slows app start-up.
- Registry cleaners: no space gained, real risk.
- Turning the page file off completely: instability and no crash dumps.

## 4. Stop it coming back

- Turn on Storage Sense (Settings → System → Storage) for temp files, the Recycle Bin and old Downloads.
- Point caches at a bigger drive: npm `npm config set cache`, pnpm `store-dir`, pip `PIP_CACHE_DIR`, uv `UV_CACHE_DIR`, Gradle `GRADLE_USER_HOME`, NuGet `NUGET_PACKAGES`, Hugging Face `HF_HOME`, Ollama `OLLAMA_MODELS`, Playwright `PLAYWRIGHT_BROWSERS_PATH`, Go `GOCACHE` / `GOMODCACHE`, Cargo `CARGO_HOME`, rustup `RUSTUP_HOME`, Maven `localRepository` in `settings.xml`.
- Move the big things: WSL distros (`wsl --manage <distro> --move`), Docker's disk image, game libraries, VMs.
- Move user folders (Downloads, Documents, Videos, Pictures: folder Properties → Location) and change "Where new content is saved" (Settings → System → Storage → Advanced storage settings).
- Put caps in place: restore-point max usage, sparse WSL disks, Telegram's cache limit, Premiere's media-cache auto-cleanup, Recall's storage limit.

## 5. Lessons from the first manual scan (24 Oct 2026, the author's PC)

Found by hand before the app existed: npm cache 9.0 GB, `C:\$GetCurrent` 3.8 GB (left over from 2020), `hiberfil.sys` 4.8 GB, `pagefile.sys` 5.1 GB, WSL `ext4.vhdx` 6.0 GB, Chrome 6.1 GB, Playwright browsers 2.6 GB, pnpm metadata cache 1.4 GB. What it taught the design:

1. Recursive PowerShell enumeration took minutes and timed out on `C:\Windows`. The app needs a native, parallel enumerator with live progress.
2. `C:\Users\All Users` is a link to `C:\ProgramData`; following links double-counts, and the manual scan did exactly that.
3. Explorer-style totals for `WinSxS` (16.5 GB here) are inflated by hard links. Use DISM's own analysis, and count each hard-linked file once.
4. Tool output comes in different encodings (`wsl.exe` writes UTF-16), and many tools translate their output into the Windows display language. Read APIs, the registry or JSON, never translated text.
5. Advice must name the right command: `pnpm store prune` cleans pnpm's package store, not the `pnpm-cache` metadata folder. Every rule needs its own accurate fix.
6. Caches contain links. Found later by COptimizer's own cleanup preview: the `pnpm-cache\dlx` folder held 1,490 junctions, some leading into pnpm's package store, which projects share through hard links. A cleaner that followed them would delete the store from under those projects. COptimizer's deleter never enters a junction.
