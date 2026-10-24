package rules

import "time"

// The catalog: docs/space-hogs.md in a form the app can apply. The texts the
// page shows for each rule are in web/i18n/rules.en.json under rule.<ID>.
//
// Pattern variables: {SystemDrive} {Windows} {ProgramData} {ProgramFiles}
// {ProgramFilesX86} {Users}, and per user {Profile} {LocalAppData} {AppData}.

// anySize reports a finding whatever its size.
const anySize = int64(1)

const (
	day  = 24 * time.Hour
	week = 7 * day
)

var catalog = []Rule{
	// Windows system files.
	{ID: "system.hiberfil", Category: System, Risk: Moderate, Min: anySize,
		Files: []string{`{SystemDrive}\hiberfil.sys`}},
	{ID: "system.pagefile", Category: System, Risk: Moderate, Min: anySize,
		Files: []string{`{SystemDrive}\pagefile.sys`}},
	{ID: "system.restore-points", Category: System, Risk: Moderate, Min: 500 * mb, Unreadable: true,
		Folders: []string{`{SystemDrive}\System Volume Information`}},
	// Only part of WinSxS can be cleaned up, and only DISM can say how much
	// (the componentStore probe), so its size isn't counted as reclaimable.
	{ID: "system.component-store", Category: System, Risk: Info, Min: gb,
		Action:  &Action{Kind: ComponentCleanup, Long: true},
		Folders: []string{`{Windows}\WinSxS`}},
	{ID: "system.installer-cache", Category: System, Risk: Info, Min: gb,
		Folders: []string{`{Windows}\Installer`}},
	{ID: "system.driver-store", Category: System, Risk: Moderate, Min: 2 * gb,
		Folders: []string{`{Windows}\System32\DriverStore\FileRepository`}},
	{ID: "system.search-index", Category: System, Risk: Moderate, Min: gb,
		Folders: []string{`{ProgramData}\Microsoft\Search\Data\Applications\Windows`}},
	{ID: "system.memory-dumps", Category: System, Risk: Safe, Min: 100 * mb, Action: del(),
		Files:   []string{`{Windows}\MEMORY.DMP`},
		Folders: []string{`{Windows}\Minidump`, `{Windows}\LiveKernelReports`}},
	{ID: "system.error-reports", Category: System, Risk: Safe, Min: 100 * mb, Action: del(),
		Folders: []string{`{ProgramData}\Microsoft\Windows\WER\ReportArchive`, `{ProgramData}\Microsoft\Windows\WER\ReportQueue`,
			`{ProgramData}\Microsoft\Windows\WER\Temp`, `{LocalAppData}\Microsoft\Windows\WER`, `{LocalAppData}\CrashDumps`}},
	{ID: "system.logs", Category: System, Risk: Safe, Min: 200 * mb,
		Action: &Action{Kind: Delete, Folders: []string{`{Windows}\Logs\CBS`, `{Windows}\Logs\DISM`},
			Include: []string{"*.log", "*.cab"}, MinAge: week},
		Folders: []string{`{Windows}\Logs\CBS`, `{Windows}\Logs\DISM`, `{Windows}\Panther`, `{ProgramData}\Microsoft\Diagnosis`,
			`{Windows}\System32\LogFiles\WMI`, `{SystemDrive}\inetpub\logs\LogFiles`}},
	{ID: "system.temp", Category: System, Risk: Safe, Min: 100 * mb, Action: &Action{Kind: Delete, MinAge: day},
		Folders: []string{`{Windows}\Temp`, `{Windows}\SystemTemp`}},
	{ID: "system.thumbnails", Category: System, Risk: Safe, Min: 200 * mb,
		Folders: []string{`{LocalAppData}\Microsoft\Windows\Explorer`}},
	{ID: "system.shader-caches", Category: System, Risk: Safe, Min: 200 * mb, Action: del(),
		Folders: []string{`{LocalAppData}\D3DSCache`, `{LocalAppData}\NVIDIA\DXCache`, `{LocalAppData}\NVIDIA\GLCache`,
			`{ProgramData}\NVIDIA Corporation\NV_Cache`, `{LocalAppData}\AMD\DxCache`, `{LocalAppData}\AMD\DxcCache`,
			`{LocalAppData}\AMD\VkCache`, `{LocalAppData}\AMD\GLCache`, `{LocalAppData}\Intel\ShaderCache`}},
	{ID: "system.print-queue", Category: System, Risk: Safe, Min: 50 * mb,
		Folders: []string{`{Windows}\System32\spool\PRINTERS`}},
	{ID: "system.recall", Category: System, Risk: Moderate, Min: gb,
		Folders: []string{`{LocalAppData}\CoreAIPlatform.00\UKP`}},
	{ID: "system.windows", Category: System, Risk: Info, Min: gb,
		Folders: []string{`{Windows}`}},
	{ID: "system.programs", Category: System, Risk: Manual, Min: gb, ItemMin: 500 * mb,
		Folders: []string{`{ProgramFiles}\*`, `{ProgramFilesX86}\*`, `{LocalAppData}\Programs\*`}},

	// Windows update and upgrade leftovers.
	{ID: "updates.windows-old", Category: Updates, Risk: Moderate, Min: 100 * mb,
		Folders: []string{`{SystemDrive}\Windows.old*`}},
	{ID: "updates.upgrade-files", Category: Updates, Risk: Moderate, Min: 100 * mb,
		Folders: []string{`{SystemDrive}\$Windows.~BT`, `{SystemDrive}\$Windows.~WS`, `{SystemDrive}\$WINDOWS.~Q`, `{SystemDrive}\ESD`}},
	// Windows10Upgrade is an installed app: it is uninstalled from Apps, not
	// deleted. $GetCurrent untouched for a week isn't part of an upgrade.
	{ID: "updates.update-assistant", Category: Updates, Risk: Safe, Min: 50 * mb,
		Action: &Action{Kind: Delete, Folders: []string{`{SystemDrive}\$GetCurrent`, `{SystemDrive}\$SysReset`},
			MinAge: week, RemoveRoot: true},
		Folders: []string{`{SystemDrive}\$GetCurrent`, `{SystemDrive}\Windows10Upgrade`, `{SystemDrive}\$SysReset`}},
	{ID: "updates.download-cache", Category: Updates, Risk: Safe, Min: 200 * mb,
		Folders: []string{`{Windows}\SoftwareDistribution\Download`}},
	{ID: "updates.delivery-optimization", Category: Updates, Risk: Safe, Min: 200 * mb,
		Action: &Action{Kind: DeliveryOptimization},
		Folders: []string{`{Windows}\SoftwareDistribution\DeliveryOptimization`,
			`{Windows}\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization`}},

	// Driver and hardware-vendor leftovers.
	{ID: "drivers.installers", Category: Drivers, Risk: Safe, Min: 200 * mb,
		Action:  &Action{Kind: Delete, MinAge: day, RemoveRoot: true},
		Folders: []string{`{SystemDrive}\NVIDIA`, `{ProgramData}\NVIDIA Corporation\Downloader`, `{SystemDrive}\AMD`, `{SystemDrive}\Intel`}},
	{ID: "drivers.oem-folders", Category: Drivers, Risk: Manual, Min: 500 * mb,
		Folders: []string{`{SystemDrive}\SWSetup`, `{SystemDrive}\Drivers`, `{SystemDrive}\Dell`}},

	// Virtual disks and emulators.
	{ID: "virtual.wsl", Category: Virtual, Risk: Moderate, Min: gb,
		Files: []string{`{LocalAppData}\wsl\*\ext4.vhdx`, `{LocalAppData}\Packages\*\LocalState\ext4.vhdx`}},
	{ID: "virtual.docker", Category: Virtual, Risk: Moderate, Min: gb,
		Files: []string{`{LocalAppData}\Docker\wsl\*\*.vhdx`}},
	{ID: "virtual.vms", Category: Virtual, Risk: Manual, Min: gb,
		Folders: []string{`{ProgramData}\Microsoft\Windows\Virtual Hard Disks`, `{Users}\Public\Documents\Hyper-V`,
			`{Profile}\VirtualBox VMs`, `{Profile}\Documents\Virtual Machines`}},
	{ID: "virtual.android", Category: Virtual, Risk: Manual, Min: gb,
		Folders: []string{`{Profile}\.android\avd`, `{ProgramData}\BlueStacks_nxt`, `{SystemDrive}\LDPlayer`,
			`{LocalAppData}\Packages\MicrosoftCorporationII.WindowsSubsystemForAndroid_8wekyb3d8bbwe`}},

	// Developer tools.
	{ID: "dev.node-modules", Category: Dev, Risk: Manual, Min: 500 * mb, ItemMin: 100 * mb,
		detect: nodeModules, stage: early},
	{ID: "dev.npm-cache", Category: Dev, Risk: Safe, Min: 200 * mb, Action: del(),
		Folders: []string{`{LocalAppData}\npm-cache`}},
	// The package store is hard-linked into projects: only `pnpm store
	// prune` knows what is unused. The metadata cache is a plain cache.
	{ID: "dev.pnpm", Category: Dev, Risk: Safe, Min: 200 * mb,
		Action:  &Action{Kind: Delete, Folders: []string{`{LocalAppData}\pnpm-cache`}},
		Folders: []string{`{LocalAppData}\pnpm-cache`, `{LocalAppData}\pnpm\store`}},
	{ID: "dev.yarn-bun", Category: Dev, Risk: Safe, Min: 200 * mb, Action: del(),
		Folders: []string{`{LocalAppData}\Yarn\Cache`, `{LocalAppData}\Yarn\Berry\cache`, `{Profile}\.bun\install\cache`}},
	{ID: "dev.browser-testing", Category: Dev, Risk: Safe, Min: 200 * mb, Action: del(),
		Folders: []string{`{LocalAppData}\ms-playwright`, `{Profile}\.cache\puppeteer`, `{LocalAppData}\Cypress\Cache`}},
	// uv's cache must not change while uv runs.
	{ID: "dev.python", Category: Dev, Risk: Safe, Min: 200 * mb, Action: del("uv.exe"),
		Folders: []string{`{LocalAppData}\pip\Cache`, `{LocalAppData}\uv\cache`, `{LocalAppData}\pypoetry\Cache`}},
	{ID: "dev.conda", Category: Dev, Risk: Safe, Min: 500 * mb,
		Folders: []string{`{Profile}\anaconda3\pkgs`, `{Profile}\miniconda3\pkgs`, `{Profile}\.conda\pkgs`,
			`{ProgramData}\anaconda3\pkgs`, `{ProgramData}\miniconda3\pkgs`}},
	{ID: "dev.nuget", Category: Dev, Risk: Safe, Min: 500 * mb, Action: del(),
		Folders: []string{`{Profile}\.nuget\packages`, `{LocalAppData}\NuGet\v3-cache`}},
	// Maven's repository can hold JARs installed by hand that no server
	// has: it is left to the user.
	{ID: "dev.gradle-maven", Category: Dev, Risk: Safe, Min: 500 * mb,
		Action:  &Action{Kind: Delete, Folders: []string{`{Profile}\.gradle\caches`, `{Profile}\.gradle\wrapper\dists`}},
		Folders: []string{`{Profile}\.gradle\caches`, `{Profile}\.gradle\wrapper\dists`, `{Profile}\.m2\repository`}},
	{ID: "dev.go", Category: Dev, Risk: Safe, Min: 500 * mb, Action: del(),
		Folders: []string{`{LocalAppData}\go-build`, `{Profile}\go\pkg\mod`}},
	{ID: "dev.rust", Category: Dev, Risk: Safe, Min: 500 * mb, Action: del(),
		Folders: []string{`{Profile}\.cargo\registry`, `{Profile}\.cargo\git`}},
	{ID: "dev.other-caches", Category: Dev, Risk: Safe, Min: 200 * mb, Action: del(),
		Folders: []string{`{LocalAppData}\electron\Cache`, `{LocalAppData}\electron-builder\Cache`, `{LocalAppData}\node-gyp\Cache`,
			`{LocalAppData}\Composer`, `{LocalAppData}\Pub\Cache`, `{LocalAppData}\deno`, `{Profile}\scoop\cache`,
			`{LocalAppData}\Temp\chocolatey`, `{ProgramData}\chocolatey\lib-bkp`, `{LocalAppData}\Temp\WinGet`}},
	{ID: "dev.vs-installer-cache", Category: Dev, Risk: Moderate, Min: gb,
		Folders: []string{`{ProgramData}\Microsoft\VisualStudio\Packages`}},
	{ID: "dev.vs-caches", Category: Dev, Risk: Safe, Min: 300 * mb, Action: del("devenv.exe"),
		Folders: []string{`{LocalAppData}\Temp\SymbolCache`, `{LocalAppData}\Microsoft\VisualStudio\*\ComponentModelCache`}},
	{ID: "dev.package-cache", Category: Dev, Risk: Info, Min: gb,
		Folders: []string{`{ProgramData}\Package Cache`}},
	{ID: "dev.toolchains", Category: Dev, Risk: Manual, Min: gb,
		Folders: []string{`{AppData}\nvm`, `{LocalAppData}\Volta`, `{Profile}\.pyenv\pyenv-win\versions`, `{Profile}\.rustup\toolchains`,
			`{Profile}\.jdks`, `{ProgramFiles}\dotnet\sdk`, `{ProgramFiles}\Java`, `{ProgramFiles}\Eclipse Adoptium`,
			`{ProgramFilesX86}\Windows Kits`, `{ProgramFiles}\NVIDIA GPU Computing Toolkit`}},
	{ID: "dev.android-sdk", Category: Dev, Risk: Manual, Min: 2 * gb,
		Folders: []string{`{LocalAppData}\Android\Sdk`}},
	{ID: "dev.editor-caches", Category: Dev, Risk: Safe, Min: 200 * mb,
		Action:  del("Code.exe", "Code - Insiders.exe", "Cursor.exe", "Windsurf.exe"),
		Folders: editorCaches(`{AppData}\Code`, `{AppData}\Code - Insiders`, `{AppData}\Cursor`, `{AppData}\Windsurf`)},
	{ID: "dev.editor-workspaces", Category: Dev, Risk: Moderate, Min: 500 * mb,
		Folders: []string{`{AppData}\Code\User\workspaceStorage`, `{AppData}\Code - Insiders\User\workspaceStorage`,
			`{AppData}\Cursor\User\workspaceStorage`, `{AppData}\Windsurf\User\workspaceStorage`}},
	{ID: "dev.editor-extensions", Category: Dev, Risk: Manual, Min: gb,
		Folders: []string{`{Profile}\.vscode\extensions`, `{Profile}\.vscode-insiders\extensions`,
			`{Profile}\.cursor\extensions`, `{Profile}\.windsurf\extensions`}},
	{ID: "dev.jetbrains", Category: Dev, Risk: Safe, Min: 500 * mb,
		Action: del("idea64.exe", "pycharm64.exe", "webstorm64.exe", "rider64.exe", "goland64.exe", "clion64.exe",
			"phpstorm64.exe", "rubymine64.exe", "datagrip64.exe", "rustrover64.exe"),
		Folders: []string{`{LocalAppData}\JetBrains\*\caches`, `{LocalAppData}\JetBrains\*\index`,
			`{LocalAppData}\JetBrains\*\log`, `{LocalAppData}\JetBrains\*\tmp`}},
	{ID: "dev.game-engines", Category: Dev, Risk: Safe, Min: gb,
		Action:  del("UnrealEditor.exe", "UE4Editor.exe", "Unity.exe"),
		Folders: []string{`{LocalAppData}\UnrealEngine\Common\DerivedDataCache`, `{LocalAppData}\Unity\cache`, `{AppData}\Unity\Asset Store-5.x`}},
	{ID: "dev.minikube", Category: Dev, Risk: Moderate, Min: gb,
		Folders: []string{`{Profile}\.minikube`}},

	// Local AI and machine learning.
	{ID: "ai.ollama", Category: AI, Risk: Manual, Min: gb,
		Folders: []string{`{Profile}\.ollama\models`}},
	{ID: "ai.huggingface", Category: AI, Risk: Manual, Min: gb,
		Folders: []string{`{Profile}\.cache\huggingface`}},
	{ID: "ai.lmstudio", Category: AI, Risk: Manual, Min: gb,
		Folders: []string{`{Profile}\.lmstudio\models`, `{Profile}\.cache\lm-studio`}},
	{ID: "ai.torch", Category: AI, Risk: Safe, Min: 500 * mb, Action: del(),
		Folders: []string{`{Profile}\.cache\torch`}},
	{ID: "ai.chrome-model", Category: AI, Risk: Safe, Min: 500 * mb, Action: del("chrome.exe"),
		Folders: []string{`{LocalAppData}\Google\Chrome\User Data\OptGuideOnDeviceModel`}},

	// Browsers.
	{ID: "browsers.chrome-cache", Category: Browsers, Risk: Safe, Min: 200 * mb, Action: del("chrome.exe"),
		Folders: chromiumCaches(`{LocalAppData}\Google\Chrome\User Data`)},
	{ID: "browsers.edge-cache", Category: Browsers, Risk: Safe, Min: 200 * mb, Action: del("msedge.exe"),
		Folders: chromiumCaches(`{LocalAppData}\Microsoft\Edge\User Data`)},
	{ID: "browsers.other-cache", Category: Browsers, Risk: Safe, Min: 200 * mb,
		Action: del("brave.exe", "vivaldi.exe", "browser.exe", "opera.exe", "firefox.exe"),
		Folders: concat(
			chromiumCaches(`{LocalAppData}\BraveSoftware\Brave-Browser\User Data`),
			chromiumCaches(`{LocalAppData}\Vivaldi\User Data`),
			chromiumCaches(`{LocalAppData}\CocCoc\Browser\User Data`),
			[]string{`{LocalAppData}\Opera Software\Opera Stable\Cache`, `{LocalAppData}\Mozilla\Firefox\Profiles\*\cache2`})},
	{ID: "browsers.profile-data", Category: Browsers, Risk: Manual, Min: gb, ItemMin: 500 * mb,
		Folders: []string{`{LocalAppData}\Google\Chrome\User Data`, `{LocalAppData}\Microsoft\Edge\User Data`,
			`{LocalAppData}\BraveSoftware\Brave-Browser\User Data`, `{LocalAppData}\Vivaldi\User Data`,
			`{LocalAppData}\CocCoc\Browser\User Data`, `{AppData}\Opera Software\Opera Stable`, `{AppData}\Mozilla\Firefox\Profiles`}},

	// Mail, chat and cloud sync.
	{ID: "apps.outlook", Category: Apps, Risk: Manual, Min: gb,
		Folders: []string{`{LocalAppData}\Microsoft\Outlook`, `{Profile}\Documents\Outlook Files`}},
	{ID: "apps.teams-cache", Category: Apps, Risk: Safe, Min: 300 * mb, Action: del("ms-teams.exe", "Teams.exe"),
		Folders: []string{`{LocalAppData}\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams`, `{AppData}\Microsoft\Teams`}},
	{ID: "apps.chat-caches", Category: Apps, Risk: Safe, Min: 200 * mb,
		Action:  del("slack.exe", "Discord.exe", "Zalo.exe", "Signal.exe"),
		Folders: electronCaches(`{AppData}\Slack`, `{AppData}\discord`, `{AppData}\ZaloData`, `{AppData}\Signal`)},
	{ID: "apps.chat-data", Category: Apps, Risk: Manual, Min: gb,
		Folders: []string{`{AppData}\ZaloData`, `{AppData}\Telegram Desktop\tdata`, `{Profile}\Downloads\Telegram Desktop`,
			`{LocalAppData}\Packages\5319275A.WhatsAppDesktop_cv1g1gvanyjgm\LocalState`}},
	{ID: "apps.cloud-sync", Category: Apps, Risk: Manual, Min: gb,
		Folders: []string{`{Profile}\OneDrive*`, `{LocalAppData}\Google\DriveFS`, `{Profile}\Dropbox`, `{Profile}\iCloudDrive`}},
	{ID: "apps.phone-backups", Category: Apps, Risk: Manual, Min: 500 * mb,
		Folders: []string{`{AppData}\Apple Computer\MobileSync\Backup`, `{Profile}\Apple\MobileSync\Backup`}},
	// No action: the cache can hold documents not yet uploaded, and only
	// Office knows which.
	{ID: "apps.office-cache", Category: Apps, Risk: Safe, Min: 300 * mb,
		Folders: []string{`{LocalAppData}\Microsoft\Office\16.0\OfficeFileCache`}},

	// Media and creative apps.
	{ID: "media.editing-caches", Category: Media, Risk: Safe, Min: 500 * mb,
		Action:  del("Adobe Premiere Pro.exe", "AfterFX.exe", "Adobe Media Encoder.exe", "Photoshop.exe", "CapCut.exe"),
		Folders: []string{`{AppData}\Adobe\Common\Media Cache Files`, `{AppData}\Adobe\Common\Media Cache`, `{LocalAppData}\CapCut\User Data\Cache`},
		Files:   []string{`{LocalAppData}\Temp\Photoshop Temp*`}},
	{ID: "media.lightroom-previews", Category: Media, Risk: Manual, Min: gb,
		Folders: []string{`{Profile}\Pictures\Lightroom\*Previews.lrdata`}},
	{ID: "media.recordings", Category: Media, Risk: Manual, Min: gb,
		Folders: []string{`{Profile}\Videos\Captures`}},
	{ID: "media.music-video", Category: Media, Risk: Manual, Min: gb,
		Folders: []string{`{LocalAppData}\Spotify\Storage`, `{LocalAppData}\Packages\SpotifyAB.SpotifyMusic_zpdnekdrzrea0\LocalCache\Spotify\Data`,
			`{LocalAppData}\Packages\4DF9E0F8.Netflix_mcm4njqhnhss8\LocalState\offlineInfo`}},

	// Games.
	{ID: "games.installed", Category: Games, Risk: Manual, Min: gb, ItemMin: gb,
		Folders: []string{`{ProgramFilesX86}\Steam\steamapps\common\*`, `{ProgramFiles}\Steam\steamapps\common\*`,
			`{ProgramFiles}\Epic Games\*`, `{SystemDrive}\XboxGames\*`, `{SystemDrive}\Riot Games\*`, `{ProgramFiles}\EA Games\*`,
			`{ProgramFilesX86}\Ubisoft\Ubisoft Game Launcher\games\*`}},
	{ID: "games.leftovers", Category: Games, Risk: Safe, Min: 500 * mb,
		Action: &Action{Kind: Delete, NeedsClosed: []string{"steam.exe", "EpicGamesLauncher.exe"},
			Folders: []string{`{ProgramFilesX86}\Steam\steamapps\shadercache`, `{ProgramFilesX86}\Steam\steamapps\temp`,
				`{ProgramFilesX86}\Steam\dumps`, `{ProgramFiles}\Steam\steamapps\shadercache`,
				`{ProgramFilesX86}\Epic Games\Launcher\VaultCache`}},
		Folders: []string{`{ProgramFilesX86}\Steam\steamapps\shadercache`, `{ProgramFilesX86}\Steam\steamapps\downloading`,
			`{ProgramFilesX86}\Steam\steamapps\temp`, `{ProgramFilesX86}\Steam\dumps`, `{ProgramFiles}\Steam\steamapps\shadercache`,
			`{ProgramFilesX86}\Epic Games\Launcher\VaultCache`}},

	// Personal files.
	{ID: "personal.downloads", Category: Personal, Risk: Manual, Min: gb,
		Folders: []string{`{Profile}\Downloads`}},
	{ID: "personal.desktop-documents", Category: Personal, Risk: Manual, Min: 2 * gb,
		Folders: []string{`{Profile}\Desktop`, `{Profile}\Documents`}},
	{ID: "personal.media", Category: Personal, Risk: Manual, Min: 2 * gb,
		Folders: []string{`{Profile}\Videos`, `{Profile}\Pictures`, `{Profile}\Music`}},
	{ID: "personal.recycle-bin", Category: Personal, Risk: Safe, Min: 100 * mb,
		Action:  &Action{Kind: EmptyRecycleBin},
		Folders: []string{`{SystemDrive}\$Recycle.Bin`}},
	{ID: "personal.temp", Category: Personal, Risk: Safe, Min: 300 * mb, Action: &Action{Kind: Delete, MinAge: day},
		Folders: []string{`{LocalAppData}\Temp`}},
	{ID: "personal.other-accounts", Category: Personal, Risk: Manual, Min: gb, ItemMin: gb,
		detect: otherAccounts, stage: late},
	{ID: "personal.big-files", Category: Personal, Risk: Manual, Min: gb, ItemMin: gb,
		detect: bigFiles, stage: late},

	// Everything else.
	{ID: "other.defender-history", Category: Other, Risk: Manual, Min: 500 * mb,
		Folders: []string{`{ProgramData}\Microsoft\Windows Defender\Scans\History`}},
	{ID: "other.big-logs", Category: Other, Risk: Manual, Min: 500 * mb, ItemMin: 500 * mb,
		detect: bigLogs, stage: late},
	{ID: "other.unrecognized", Category: Other, Risk: Manual, Min: anySize,
		detect: unrecognized, stage: last},
	{ID: "other.growth", Category: Other, Risk: Info, Min: anySize, noTotal: true,
		detect: growth, stage: last},
}

// del is a Delete action for all of a rule's locations, with the programs
// that must be closed first.
func del(needsClosed ...string) *Action { return &Action{Kind: Delete, NeedsClosed: needsClosed} }

// chromiumCaches are the cache folders of a Chromium-based browser, given its
// User Data folder: per profile, plus the shared shader caches.
func chromiumCaches(userData string) []string {
	return []string{
		userData + `\*\Cache`, userData + `\*\Code Cache`, userData + `\*\GPUCache`,
		userData + `\*\Service Worker\CacheStorage`, userData + `\*\Service Worker\ScriptCache`,
		userData + `\ShaderCache`, userData + `\GrShaderCache`, userData + `\GraphiteDawnCache`,
	}
}

// electronCaches are the cache folders of Electron apps, given their data
// folders.
func electronCaches(dirs ...string) []string {
	var out []string
	for _, d := range dirs {
		out = append(out, d+`\Cache`, d+`\Code Cache`, d+`\GPUCache`, d+`\DawnCache`, d+`\Service Worker\CacheStorage`)
	}
	return out
}

// editorCaches are the cache folders of VS Code-like editors.
func editorCaches(dirs ...string) []string {
	var out []string
	for _, d := range dirs {
		out = append(out, d+`\Cache`, d+`\CachedData`, d+`\CachedExtensionVSIXs`, d+`\Code Cache`, d+`\GPUCache`, d+`\logs`)
	}
	return out
}

func concat(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}
