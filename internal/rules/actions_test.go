package rules_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ntson9p/coptimizer/internal/fsx/memfs"
	"github.com/ntson9p/coptimizer/internal/rules"
	"github.com/ntson9p/coptimizer/internal/safety"
)

// deletable lists every location a Delete action may clean, with its
// options. Changing what COptimizer may delete is a security-relevant change:
// this list makes it show up in review.
var deletable = []string{
	"system.memory-dumps: {Windows}\\Minidump",
	"system.memory-dumps: {Windows}\\LiveKernelReports",
	"system.memory-dumps: file {Windows}\\MEMORY.DMP",
	"system.error-reports: {ProgramData}\\Microsoft\\Windows\\WER\\ReportArchive",
	"system.error-reports: {ProgramData}\\Microsoft\\Windows\\WER\\ReportQueue",
	"system.error-reports: {ProgramData}\\Microsoft\\Windows\\WER\\Temp",
	"system.error-reports: {LocalAppData}\\Microsoft\\Windows\\WER",
	"system.error-reports: {LocalAppData}\\CrashDumps",
	"system.logs: {Windows}\\Logs\\CBS (only *.log *.cab, older than 168h0m0s)",
	"system.logs: {Windows}\\Logs\\DISM (only *.log *.cab, older than 168h0m0s)",
	"system.temp: {Windows}\\Temp (older than 24h0m0s)",
	"system.temp: {Windows}\\SystemTemp (older than 24h0m0s)",
	"system.shader-caches: {LocalAppData}\\D3DSCache",
	"system.shader-caches: {LocalAppData}\\NVIDIA\\DXCache",
	"system.shader-caches: {LocalAppData}\\NVIDIA\\GLCache",
	"system.shader-caches: {ProgramData}\\NVIDIA Corporation\\NV_Cache",
	"system.shader-caches: {LocalAppData}\\AMD\\DxCache",
	"system.shader-caches: {LocalAppData}\\AMD\\DxcCache",
	"system.shader-caches: {LocalAppData}\\AMD\\VkCache",
	"system.shader-caches: {LocalAppData}\\AMD\\GLCache",
	"system.shader-caches: {LocalAppData}\\Intel\\ShaderCache",
	"updates.update-assistant: {SystemDrive}\\$GetCurrent (older than 168h0m0s, folder too)",
	"updates.update-assistant: {SystemDrive}\\$SysReset (older than 168h0m0s, folder too)",
	"drivers.installers: {SystemDrive}\\NVIDIA (older than 24h0m0s, folder too)",
	"drivers.installers: {ProgramData}\\NVIDIA Corporation\\Downloader (older than 24h0m0s, folder too)",
	"drivers.installers: {SystemDrive}\\AMD (older than 24h0m0s, folder too)",
	"drivers.installers: {SystemDrive}\\Intel (older than 24h0m0s, folder too)",
	"dev.npm-cache: {LocalAppData}\\npm-cache",
	"dev.pnpm: {LocalAppData}\\pnpm-cache",
	"dev.yarn-bun: {LocalAppData}\\Yarn\\Cache",
	"dev.yarn-bun: {LocalAppData}\\Yarn\\Berry\\cache",
	"dev.yarn-bun: {Profile}\\.bun\\install\\cache",
	"dev.browser-testing: {LocalAppData}\\ms-playwright",
	"dev.browser-testing: {Profile}\\.cache\\puppeteer",
	"dev.browser-testing: {LocalAppData}\\Cypress\\Cache",
	"dev.python: {LocalAppData}\\pip\\Cache",
	"dev.python: {LocalAppData}\\uv\\cache",
	"dev.python: {LocalAppData}\\pypoetry\\Cache",
	"dev.nuget: {Profile}\\.nuget\\packages",
	"dev.nuget: {LocalAppData}\\NuGet\\v3-cache",
	"dev.gradle-maven: {Profile}\\.gradle\\caches",
	"dev.gradle-maven: {Profile}\\.gradle\\wrapper\\dists",
	"dev.go: {LocalAppData}\\go-build",
	"dev.go: {Profile}\\go\\pkg\\mod",
	"dev.rust: {Profile}\\.cargo\\registry",
	"dev.rust: {Profile}\\.cargo\\git",
	"dev.other-caches: {LocalAppData}\\electron\\Cache",
	"dev.other-caches: {LocalAppData}\\electron-builder\\Cache",
	"dev.other-caches: {LocalAppData}\\node-gyp\\Cache",
	"dev.other-caches: {LocalAppData}\\Composer",
	"dev.other-caches: {LocalAppData}\\Pub\\Cache",
	"dev.other-caches: {LocalAppData}\\deno",
	"dev.other-caches: {Profile}\\scoop\\cache",
	"dev.other-caches: {LocalAppData}\\Temp\\chocolatey",
	"dev.other-caches: {ProgramData}\\chocolatey\\lib-bkp",
	"dev.other-caches: {LocalAppData}\\Temp\\WinGet",
	"dev.vs-caches: {LocalAppData}\\Temp\\SymbolCache",
	"dev.vs-caches: {LocalAppData}\\Microsoft\\VisualStudio\\*\\ComponentModelCache",
	"dev.editor-caches: {AppData}\\Code\\Cache",
	"dev.editor-caches: {AppData}\\Code\\CachedData",
	"dev.editor-caches: {AppData}\\Code\\CachedExtensionVSIXs",
	"dev.editor-caches: {AppData}\\Code\\Code Cache",
	"dev.editor-caches: {AppData}\\Code\\GPUCache",
	"dev.editor-caches: {AppData}\\Code\\logs",
	"dev.editor-caches: {AppData}\\Code - Insiders\\Cache",
	"dev.editor-caches: {AppData}\\Code - Insiders\\CachedData",
	"dev.editor-caches: {AppData}\\Code - Insiders\\CachedExtensionVSIXs",
	"dev.editor-caches: {AppData}\\Code - Insiders\\Code Cache",
	"dev.editor-caches: {AppData}\\Code - Insiders\\GPUCache",
	"dev.editor-caches: {AppData}\\Code - Insiders\\logs",
	"dev.editor-caches: {AppData}\\Cursor\\Cache",
	"dev.editor-caches: {AppData}\\Cursor\\CachedData",
	"dev.editor-caches: {AppData}\\Cursor\\CachedExtensionVSIXs",
	"dev.editor-caches: {AppData}\\Cursor\\Code Cache",
	"dev.editor-caches: {AppData}\\Cursor\\GPUCache",
	"dev.editor-caches: {AppData}\\Cursor\\logs",
	"dev.editor-caches: {AppData}\\Windsurf\\Cache",
	"dev.editor-caches: {AppData}\\Windsurf\\CachedData",
	"dev.editor-caches: {AppData}\\Windsurf\\CachedExtensionVSIXs",
	"dev.editor-caches: {AppData}\\Windsurf\\Code Cache",
	"dev.editor-caches: {AppData}\\Windsurf\\GPUCache",
	"dev.editor-caches: {AppData}\\Windsurf\\logs",
	"dev.jetbrains: {LocalAppData}\\JetBrains\\*\\caches",
	"dev.jetbrains: {LocalAppData}\\JetBrains\\*\\index",
	"dev.jetbrains: {LocalAppData}\\JetBrains\\*\\log",
	"dev.jetbrains: {LocalAppData}\\JetBrains\\*\\tmp",
	"dev.game-engines: {LocalAppData}\\UnrealEngine\\Common\\DerivedDataCache",
	"dev.game-engines: {LocalAppData}\\Unity\\cache",
	"dev.game-engines: {AppData}\\Unity\\Asset Store-5.x",
	"ai.torch: {Profile}\\.cache\\torch",
	"ai.chrome-model: {LocalAppData}\\Google\\Chrome\\User Data\\OptGuideOnDeviceModel",
	"browsers.chrome-cache: {LocalAppData}\\Google\\Chrome\\User Data\\*\\Cache",
	"browsers.chrome-cache: {LocalAppData}\\Google\\Chrome\\User Data\\*\\Code Cache",
	"browsers.chrome-cache: {LocalAppData}\\Google\\Chrome\\User Data\\*\\GPUCache",
	"browsers.chrome-cache: {LocalAppData}\\Google\\Chrome\\User Data\\*\\Service Worker\\CacheStorage",
	"browsers.chrome-cache: {LocalAppData}\\Google\\Chrome\\User Data\\*\\Service Worker\\ScriptCache",
	"browsers.chrome-cache: {LocalAppData}\\Google\\Chrome\\User Data\\ShaderCache",
	"browsers.chrome-cache: {LocalAppData}\\Google\\Chrome\\User Data\\GrShaderCache",
	"browsers.chrome-cache: {LocalAppData}\\Google\\Chrome\\User Data\\GraphiteDawnCache",
	"browsers.edge-cache: {LocalAppData}\\Microsoft\\Edge\\User Data\\*\\Cache",
	"browsers.edge-cache: {LocalAppData}\\Microsoft\\Edge\\User Data\\*\\Code Cache",
	"browsers.edge-cache: {LocalAppData}\\Microsoft\\Edge\\User Data\\*\\GPUCache",
	"browsers.edge-cache: {LocalAppData}\\Microsoft\\Edge\\User Data\\*\\Service Worker\\CacheStorage",
	"browsers.edge-cache: {LocalAppData}\\Microsoft\\Edge\\User Data\\*\\Service Worker\\ScriptCache",
	"browsers.edge-cache: {LocalAppData}\\Microsoft\\Edge\\User Data\\ShaderCache",
	"browsers.edge-cache: {LocalAppData}\\Microsoft\\Edge\\User Data\\GrShaderCache",
	"browsers.edge-cache: {LocalAppData}\\Microsoft\\Edge\\User Data\\GraphiteDawnCache",
	"browsers.other-cache: {LocalAppData}\\BraveSoftware\\Brave-Browser\\User Data\\*\\Cache",
	"browsers.other-cache: {LocalAppData}\\BraveSoftware\\Brave-Browser\\User Data\\*\\Code Cache",
	"browsers.other-cache: {LocalAppData}\\BraveSoftware\\Brave-Browser\\User Data\\*\\GPUCache",
	"browsers.other-cache: {LocalAppData}\\BraveSoftware\\Brave-Browser\\User Data\\*\\Service Worker\\CacheStorage",
	"browsers.other-cache: {LocalAppData}\\BraveSoftware\\Brave-Browser\\User Data\\*\\Service Worker\\ScriptCache",
	"browsers.other-cache: {LocalAppData}\\BraveSoftware\\Brave-Browser\\User Data\\ShaderCache",
	"browsers.other-cache: {LocalAppData}\\BraveSoftware\\Brave-Browser\\User Data\\GrShaderCache",
	"browsers.other-cache: {LocalAppData}\\BraveSoftware\\Brave-Browser\\User Data\\GraphiteDawnCache",
	"browsers.other-cache: {LocalAppData}\\Vivaldi\\User Data\\*\\Cache",
	"browsers.other-cache: {LocalAppData}\\Vivaldi\\User Data\\*\\Code Cache",
	"browsers.other-cache: {LocalAppData}\\Vivaldi\\User Data\\*\\GPUCache",
	"browsers.other-cache: {LocalAppData}\\Vivaldi\\User Data\\*\\Service Worker\\CacheStorage",
	"browsers.other-cache: {LocalAppData}\\Vivaldi\\User Data\\*\\Service Worker\\ScriptCache",
	"browsers.other-cache: {LocalAppData}\\Vivaldi\\User Data\\ShaderCache",
	"browsers.other-cache: {LocalAppData}\\Vivaldi\\User Data\\GrShaderCache",
	"browsers.other-cache: {LocalAppData}\\Vivaldi\\User Data\\GraphiteDawnCache",
	"browsers.other-cache: {LocalAppData}\\CocCoc\\Browser\\User Data\\*\\Cache",
	"browsers.other-cache: {LocalAppData}\\CocCoc\\Browser\\User Data\\*\\Code Cache",
	"browsers.other-cache: {LocalAppData}\\CocCoc\\Browser\\User Data\\*\\GPUCache",
	"browsers.other-cache: {LocalAppData}\\CocCoc\\Browser\\User Data\\*\\Service Worker\\CacheStorage",
	"browsers.other-cache: {LocalAppData}\\CocCoc\\Browser\\User Data\\*\\Service Worker\\ScriptCache",
	"browsers.other-cache: {LocalAppData}\\CocCoc\\Browser\\User Data\\ShaderCache",
	"browsers.other-cache: {LocalAppData}\\CocCoc\\Browser\\User Data\\GrShaderCache",
	"browsers.other-cache: {LocalAppData}\\CocCoc\\Browser\\User Data\\GraphiteDawnCache",
	"browsers.other-cache: {LocalAppData}\\Opera Software\\Opera Stable\\Cache",
	"browsers.other-cache: {LocalAppData}\\Mozilla\\Firefox\\Profiles\\*\\cache2",
	"apps.teams-cache: {LocalAppData}\\Packages\\MSTeams_8wekyb3d8bbwe\\LocalCache\\Microsoft\\MSTeams",
	"apps.teams-cache: {AppData}\\Microsoft\\Teams",
	"apps.chat-caches: {AppData}\\Slack\\Cache",
	"apps.chat-caches: {AppData}\\Slack\\Code Cache",
	"apps.chat-caches: {AppData}\\Slack\\GPUCache",
	"apps.chat-caches: {AppData}\\Slack\\DawnCache",
	"apps.chat-caches: {AppData}\\Slack\\Service Worker\\CacheStorage",
	"apps.chat-caches: {AppData}\\discord\\Cache",
	"apps.chat-caches: {AppData}\\discord\\Code Cache",
	"apps.chat-caches: {AppData}\\discord\\GPUCache",
	"apps.chat-caches: {AppData}\\discord\\DawnCache",
	"apps.chat-caches: {AppData}\\discord\\Service Worker\\CacheStorage",
	"apps.chat-caches: {AppData}\\ZaloData\\Cache",
	"apps.chat-caches: {AppData}\\ZaloData\\Code Cache",
	"apps.chat-caches: {AppData}\\ZaloData\\GPUCache",
	"apps.chat-caches: {AppData}\\ZaloData\\DawnCache",
	"apps.chat-caches: {AppData}\\ZaloData\\Service Worker\\CacheStorage",
	"apps.chat-caches: {AppData}\\Signal\\Cache",
	"apps.chat-caches: {AppData}\\Signal\\Code Cache",
	"apps.chat-caches: {AppData}\\Signal\\GPUCache",
	"apps.chat-caches: {AppData}\\Signal\\DawnCache",
	"apps.chat-caches: {AppData}\\Signal\\Service Worker\\CacheStorage",
	"media.editing-caches: {AppData}\\Adobe\\Common\\Media Cache Files",
	"media.editing-caches: {AppData}\\Adobe\\Common\\Media Cache",
	"media.editing-caches: {LocalAppData}\\CapCut\\User Data\\Cache",
	"media.editing-caches: file {LocalAppData}\\Temp\\Photoshop Temp*",
	"games.leftovers: {ProgramFilesX86}\\Steam\\steamapps\\shadercache",
	"games.leftovers: {ProgramFilesX86}\\Steam\\steamapps\\temp",
	"games.leftovers: {ProgramFilesX86}\\Steam\\dumps",
	"games.leftovers: {ProgramFiles}\\Steam\\steamapps\\shadercache",
	"games.leftovers: {ProgramFilesX86}\\Epic Games\\Launcher\\VaultCache",
	"personal.temp: {LocalAppData}\\Temp (older than 24h0m0s)",
}

// deletableLocations describes the locations of every Delete action.
func deletableLocations() []string {
	var out []string
	for _, r := range rules.Rules() {
		a := r.Action
		if a == nil || a.Kind != rules.Delete {
			continue
		}
		var opts []string
		if len(a.Include) > 0 {
			opts = append(opts, "only "+strings.Join(a.Include, " "))
		}
		if a.MinAge > 0 {
			opts = append(opts, "older than "+a.MinAge.String())
		}
		if a.RemoveRoot {
			opts = append(opts, "folder too")
		}
		suffix := ""
		if len(opts) > 0 {
			suffix = " (" + strings.Join(opts, ", ") + ")"
		}
		folders := r.Folders
		if a.Folders != nil {
			folders = a.Folders
		}
		for _, f := range folders {
			out = append(out, r.ID+": "+f+suffix)
		}
		for _, f := range r.Files {
			out = append(out, r.ID+": file "+f+suffix)
		}
	}
	return out
}

func TestDeletableLocationsAreReviewed(t *testing.T) {
	got := deletableLocations()
	if !slices.Equal(got, deletable) {
		var b strings.Builder
		for _, l := range got {
			fmt.Fprintf(&b, "\t%q,\n", l)
		}
		t.Errorf("the locations Delete actions may clean changed. Review the change, then update deletable to:\n%s", b.String())
	}
}

func TestActionsFitTheirRules(t *testing.T) {
	kinds := map[rules.ActionKind]bool{rules.Delete: true, rules.EmptyRecycleBin: true, rules.ComponentCleanup: true, rules.DeliveryOptimization: true}
	for _, r := range rules.Rules() {
		a := r.Action
		if a == nil {
			continue
		}
		if !kinds[a.Kind] {
			t.Errorf("%s: unknown action kind %q", r.ID, a.Kind)
		}
		if a.Kind == rules.Delete && r.Risk != rules.Safe {
			t.Errorf("%s: a %s finding can't be deleted by COptimizer", r.ID, r.Risk)
		}
		if a.Kind != rules.Delete && (a.Folders != nil || a.Include != nil || a.MinAge != 0 || a.RemoveRoot) {
			t.Errorf("%s: only Delete actions take folders and filters", r.ID)
		}
		for _, f := range a.Folders {
			if !slices.Contains(r.Folders, f) {
				t.Errorf("%s: the action's folder %q isn't one of the rule's", r.ID, f)
			}
		}
		for _, p := range a.NeedsClosed {
			if !strings.HasSuffix(p, ".exe") || strings.ContainsAny(p, `\/`) {
				t.Errorf("%s: %q isn't a program name", r.ID, p)
			}
		}
		if a.MinAge < 0 {
			t.Errorf("%s: negative MinAge", r.ID)
		}
	}
}

// TestEveryDeletableLocationPassesThePolicy expands every Delete location on
// a standard PC and asks the deny list about it: an action the policy would
// refuse at run time is a mistake in the catalog or in the policy.
func TestEveryDeletableLocationPassesThePolicy(t *testing.T) {
	env := rules.DefaultEnv("alice")
	p, err := safety.NewPolicy(safety.Places{SystemDrive: env.SystemDrive, Windows: env.Windows, ProgramData: env.ProgramData,
		ProgramFiles: env.ProgramFiles, ProgramFilesX86: env.ProgramFilesX86, Users: env.Users})
	if err != nil {
		t.Fatal(err)
	}
	expand := strings.NewReplacer(
		"{SystemDrive}", env.SystemDrive, "{Windows}", env.Windows, "{ProgramData}", env.ProgramData,
		"{ProgramFiles}", env.ProgramFiles, "{ProgramFilesX86}", env.ProgramFilesX86, "{Users}", env.Users,
		"{Profile}", env.CurrentProfile, "{LocalAppData}", env.CurrentProfile+`\AppData\Local`,
		"{AppData}", env.CurrentProfile+`\AppData\Roaming`, "*", "x", "?", "x")
	for _, r := range rules.Rules() {
		if r.Action == nil || r.Action.Kind != rules.Delete {
			continue
		}
		folders := r.Folders
		if r.Action.Folders != nil {
			folders = r.Action.Folders
		}
		for _, pat := range append(slices.Clone(folders), r.Files...) {
			if err := p.Check(expand.Replace(pat)); err != nil {
				t.Errorf("%s: %s: %v", r.ID, pat, err)
			}
		}
	}
}

func TestReportKeepsEveryLocationAndWhatOthersClaim(t *testing.T) {
	f := memfs.New()
	local := `C:\Users\Asus\AppData\Local`
	for i := range 60 {
		f.AddFile(fmt.Sprintf(`%s\Google\Chrome\User Data\Profile %d\Cache\Cache_Data\f`, local, i), 10*mb, t0)
	}
	f.AddFile(local+`\Temp\a.tmp`, 400*mb, t0)
	f.AddFile(local+`\Temp\SymbolCache\x.pdb`, 400*mb, t0)
	f.AddFile(local+`\Temp\WinGet\x.msi`, 300*mb, t0)
	rep := evaluate(t, f)

	chrome, ok := rep.Find("browsers.chrome-cache")
	if !ok || len(chrome.Items) != 50 || chrome.MoreItems != 10 || len(rep.Locations("browsers.chrome-cache")) != 60 {
		t.Fatalf("chrome: %d items, %d more, %d locations", len(chrome.Items), chrome.MoreItems, len(rep.Locations("browsers.chrome-cache")))
	}
	if chrome.Action == nil || chrome.Action.Kind != rules.Delete || !slices.Contains(chrome.Action.NeedsClosed, "chrome.exe") {
		t.Errorf("chrome action = %+v", chrome.Action)
	}
	got := rep.ClaimedInside("personal.temp", local+`\Temp`)
	want := []string{local + `\Temp\SymbolCache`, local + `\Temp\WinGet`}
	if !slices.Equal(got, want) {
		t.Errorf("claimed inside Temp = %v; want %v", got, want)
	}
	if _, ok := rep.Find("no.such"); ok {
		t.Error("found a finding that doesn't exist")
	}
}

func TestActionAgesAreSensible(t *testing.T) {
	for _, r := range rules.Rules() {
		if r.Action != nil && r.Action.MinAge > 30*24*time.Hour {
			t.Errorf("%s: MinAge %v is longer than a month", r.ID, r.Action.MinAge)
		}
	}
}
