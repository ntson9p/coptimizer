# COptimizer: implementation plan

Status: phases 0–2 done (test safety fuses; read-only scanner, server, launcher and web page; findings and system information). Phase 3 (safe cleanups) is built and tested; its real runs on a PC are the last step (section 14). Companion documents: [space-hogs.md](space-hogs.md) (what the app looks for) and [testing.md](testing.md) (how it's tested without risking anyone's PC).

## 1. Goal

A local web app that finds what is filling the Windows system drive and helps reclaim the space safely.

- **Server**: one Windows executable written in Go. It runs as Administrator and listens on `127.0.0.1` only.
- **Client**: a static HTML/CSS/JS page served by the server and built into the exe. It controls scans and actions and shows their live status.
- **Use**: double-click `coptimizer.exe`, accept the UAC prompt, and the dashboard opens in your normal browser.

What it does:

1. Scans C: (other drives optional) quickly and accurately: folder tree, biggest files, file types, space nothing accounts for.
2. Recognizes the ~100 known space hogs in space-hogs.md. For each: its size, why it grows, what cleaning costs and how to stop it coming back.
3. Cleans safely: preview, confirm, run, verify, with live progress and an audit log.
4. Finds what no rule knows: big unrecognized folders, and folders that grew since the last scan.
5. Suggests moving space-hungry things to a drive with room.

Out of scope for v1 (phases 0–4):

- Deleting personal files (Documents, Downloads, Desktop, photos, projects). The app shows them and opens Explorer; you decide.
- Registry cleaning, "debloating" Windows, removing drivers outside Microsoft's own tools.
- Remote access, managing several machines, telemetry, running as a background service.

## 2. Decisions

| Topic | Choice | Reason |
|---|---|---|
| Server language | Go, the version in `go.mod` (1.27 today; at least 1.24 for `os.Root`) | One small `.exe`, nothing for users to install. Reads names, sizes and attributes of many directory entries per system call without opening files, and goroutines make parallel scanning simple. Standard-library HTTP server and `embed` for the UI; `golang.org/x/sys/windows` for Win32 APIs; built-in testing and fuzzing. |
| Considered | C# / .NET 10, Node.js / TypeScript, Rust | .NET: the best Windows API access, but users need the runtime or a 35–70 MB exe; kept as the fallback if Go can't reach an API cleanly. Node: slower scans (one extra system call per file), native add-ons for Windows APIs, a large bundled exe. Rust: fastest, but slowest to write and needs several GB of C++ build tools. |
| Client | Plain HTML, CSS and JavaScript modules; no framework, no build step | Small and easy to audit. No npm dependency tree inside a tool that runs as Administrator. |
| Live status | Server-Sent Events, read with `fetch()` | Progress and logs only flow from server to browser. `fetch()` can send the auth header; `EventSource` can't. |
| Dependencies | Go standard library, `golang.org/x/sys`, `golang.org/x/text` | Smallest possible supply chain: no CDN, no third-party UI code. |
| App data | `<exe folder>\data\` | Keeps the app's own files off C: when the exe lives elsewhere. During development it stays inside the repository folder (git-ignored). |
| Windows versions | Windows 10 22H2 and Windows 11, x64 (arm64 later) | |
| Units | Binary (1 GB = 1024³ bytes) | Numbers match what Explorer shows. |
| Drives | C: by default; other fixed drives can be added to a scan | C: is the drive that fills up; scanning every drive would take several times longer. |
| Publishing | Open source on GitHub from day one, MIT license | Anyone can read the code of a tool that runs as Administrator before trusting it; MIT is the simplest and most common license for Go tools. |
| Interface language | English, with every string in a translation file from day one; Vietnamese in phase 5 | No double work while the UI still changes a lot; adding a language later is one file. |

## 3. Architecture

### 3.1 How it starts

A browser started by an Administrator process would itself run as Administrator, which is unsafe. So the exe runs twice: once unelevated to launch, once elevated to serve.

```
coptimizer.exe, started normally (unelevated): the "launcher"
  1. picks a free port P and creates a one-time launch code
  2. relaunches itself elevated (UAC prompt):
       coptimizer.exe --serve --port P --launch-code <code> --user-sid <SID>
  3. waits until http://127.0.0.1:P/healthz answers with a hash of the launch code
     (proves it is talking to its own server, not something else on that port)
  4. opens the default browser, unelevated, at http://127.0.0.1:P/#code=<code>
  5. exits

coptimizer.exe --serve (elevated): the "server"; its console window stays open
  ├─ HTTP server on 127.0.0.1:P: embedded UI, JSON API, event stream
  ├─ scan engine: parallel walker → in-memory folder tree
  ├─ rule engine: catalog of detectors → findings
  ├─ job manager: one changing action at a time, cancel, progress
  ├─ executors: safe deleter, command runner, Disk Cleanup and DISM adapters
  └─ store: config, history, scan snapshots in <exe folder>\data
  console keys: L prints a fresh one-time link, Q quits
```

Started from an elevated terminal (no launcher), the server prints the link and tries `explorer.exe <url>`, which hands the URL to the user's unelevated shell.

Phase 4 adds an unelevated helper for user tools (`pnpm`, `conda`, `docker`, `wsl`): the launcher stays in the background as the signed-in user and runs only the catalog's commands, so those tools never run with Administrator rights (section 7.3). Phase 3's cleanups need no helper: they are deletions by COptimizer itself and Windows' own tools.

If the elevated account is a different one (a standard user typed an administrator's password), "your" profile is the administrator's: the standard user's caches count as another account's and are left alone (section 5.1).

### 3.2 Components

```
browser UI ──HTTP + events──► server ──► jobs ──► actions ──► safety ──► winfs · execx · sysinfo
                                │                    ▲
                                ├──► scan ───────────┘   (the tree feeds rules and previews)
                                ├──► rules ──► scan · sysinfo · execx   (read-only probes)
                                └──► store
```

| Package | Responsibility |
|---|---|
| `cmd/coptimizer` | Flags, launcher and elevation flow, wiring of real or demo implementations |
| `internal/server` | Routes, auth / Host / Origin middleware, event hub, handlers |
| `internal/scan` | Parallel traversal, folder tree, top files, file types, snapshots and diffs |
| `internal/winfs` | Windows directory enumeration, backup privilege, size on disk, reparse-point and cloud-placeholder detection |
| `internal/fsx` | Filesystem interfaces, plus an in-memory fake for tests and demo mode |
| `internal/rules` | Rule model, catalog with each rule's action, per-user expansion, smart findings |
| `internal/probe` | Read-only system information: power, WSL, DISM analyses, known folders |
| `internal/actions` | Plans (dry runs) and runs of the catalog's actions: deletions, the Recycle Bin, DISM component cleanup, Delivery Optimization |
| `internal/clean` | The deleter: confined to one folder handle, checks the deny list for every entry, dry runs that decide like real ones |
| `internal/safety` | Path normalization, the deny list, test fuses |
| `internal/execx` | Command runner (Job Objects, timeouts, line-by-line output), plus a fake runner |
| `internal/sysinfo` | Drives, elevation, running programs, Recycle Bin size (`Reader`, `Programs`, `RecycleBinReader`); emptying the Recycle Bin is `Mutator`'s alone |
| `internal/store` | Scan snapshots, `history.jsonl` |
| `internal/server` | Also the cleanup queue (`jobs.go`): previews, one cleanup at a time, progress events, history, measuring folders again |
| `internal/testguard` | Shared `TestMain`: refuses elevated test runs, arms the fuses |
| `web/` | The client, embedded with `go:embed` |

## 4. Security

The server runs as Administrator and can delete files, so the API is designed as if every caller were hostile.

| Threat | Defense |
|---|---|
| Other computers on the network | Listen on `127.0.0.1` only; refuse to start on any other address |
| A web page in your browser calling `localhost` (CSRF) | Every API call needs `Authorization: Bearer <session token>`. That header forces a CORS preflight, and the server sends no CORS headers, so browsers block foreign pages. Changing requests must also carry our own `Origin` |
| DNS rebinding | Reject any request whose `Host` isn't `127.0.0.1:P` or `localhost:P` |
| Token leaking through URLs or history | The URL carries only a one-time launch code, in the `#fragment`, which is never sent to the server. The page exchanges it once for a session token kept in `sessionStorage`. The code expires after first use or 2 minutes |
| Other local users | 256-bit random token; new links only from the elevated console window |
| Script injection through file names, registry values or command output | All of these are untrusted data: rendered with `textContent`, never `innerHTML`. Strict CSP `default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'`, plus `X-Content-Type-Options: nosniff` |
| Using the elevated API to delete or run arbitrary things | The API never accepts a path to delete or a command to run: a preview names a finding (`ruleId`), a cleanup names a preview (`planId`), and the server works out the folders from the catalog and the latest scan. JSON decoding rejects unknown fields |
| Supply chain | Only Go-project modules; zero third-party UI code |
| Running tools | Arguments passed as arrays, never through a shell. Only Windows' own tools, by absolute path in System32 (`dism.exe`, `powershell.exe`); the preview shows the exact command line. User tools wait for the unelevated helper (phase 4) |
| Junctions planted in a cache by malware, to make the elevated deleter delete elsewhere | Each folder is opened as an `os.Root` and Windows is asked where it really is; every later step names paths relative to that handle, and Go refuses any path through a junction. A folder swapped for a junction mid-run can't redirect it (tested). Measuring a cleaned folder again first looks it up in its parent, so a junction swapped in afterwards is kept as a link, not measured through |
| A junction made of COptimizer's own data folder, to make the elevated server write elsewhere | The data folder is opened the same way, and the history and snapshots are written only through its handle (tested) |
| Ctrl+C in the server's console reaching the tools it runs | Tools get no console of their own to share: Windows gives each a separate one without a window (tested: the tool's console has no other process) |
| Privileges | Enables `SeBackupPrivilege` to *measure* protected folders. Never enables `SeRestorePrivilege` or `SeTakeOwnershipPrivilege`, so file permissions still stop us deleting protected files |

## 5. Safety model

### 5.1 Golden rules, enforced in code

1. **The page never names what to delete.** A preview request names a finding (`ruleId`), a cleanup request names a preview (`planId`); the folders come from the catalog and the latest scan, on the server.
2. **Deletes happen only inside a rule's declared folders**, and never on the deny list (5.2), even if a rule asks. A test lists every folder an action may clean, so any change to that list shows up in review.
3. **Your own files only.** Per-user locations are cleaned only in your own profile; other accounts' caches are reported and left alone. Windows' folders are cleaned only with Administrator rights.
4. **Use the owner's tool first**: DISM for the component store, the Delivery Optimization service for its cache, the shell for the Recycle Bin. Raw deletion is only for plain caches, temporary files, logs and dumps. Where only the owner's tool knows what is safe (`pnpm store prune`, `conda clean`), the action leaves that location to it.
5. **Never follow reparse points** (junctions, symlinks, mount points, cloud placeholders). One found inside a cache folder is left alone, not entered. On a real PC, pnpm's `dlx` cache held 1,490 junctions, some into the package store that projects hard-link to: following them would have deleted the store.
6. **A preview always comes first**, worked out by a dry run of the same code, and it runs as shown: a preview made in simulation mode can only be a simulation, and one made without it only a real cleanup; if the mode changes in between, the cleanup is refused and the page previews again. Moderate actions (phase 4) also need a ticked acknowledgement that states the trade-off and how to undo it.
7. **Skip files that are in use; never kill processes.** If an app must be closed first (`chrome.exe` for its cache), the preview says so and the cleanup won't start until it is closed.
8. **Fail closed.** Anything that can't be resolved or validated is skipped and reported.
9. **Measure the result.** Free space before and after, per-location totals, and an entry in `history.jsonl`. The cleaned folders are measured again and the findings updated.
10. **One cleanup at a time**, in the order confirmed. The page's Quit is refused while one is queued or running; in the console window, Q or Ctrl+C must be given twice within 30 seconds. Once stopping has begun, no new cleanup starts.
11. **Simulation mode**, a switch on the Activity page (or `-simulate`), turns every cleanup into a dry run.

### 5.2 Deny list

The deleter checks every folder and every file against the deny list (`internal/safety/policy.go`), whatever a rule says:

- **Protected trees**, where nothing may be deleted: `C:\Windows`, `C:\Program Files`, `C:\Program Files (x86)`, `C:\ProgramData\Package Cache`, `System Volume Information`, `$Recycle.Bin` (emptied only through Windows), `Recovery`, `$WinREAgent`, `Windows.old*`, `$Windows.~BT`, `$Windows.~WS`, `C:\Users\Public`, `Default`, `Default User`, `All Users`; in every profile Desktop, Documents, Downloads, Pictures, Videos, Music, Favorites, Contacts, Links, Saved Games, Searches, 3D Objects and `OneDrive*`; and the current user's personal folders wherever they were moved (read from the registry).
- **Exceptions** inside them, each used by an action: `Windows\Temp`, `SystemTemp`, `Logs\CBS`, `Logs\DISM`, `Minidump`, `LiveKernelReports`, `MEMORY.DMP`; Steam's `shadercache`, `temp` and `dumps`, and Epic's `VaultCache`. An exception only counts against a shallower tree, so a personal folder moved inside one stays protected.
- **General folders** that may not be deleted or emptied themselves, though folders inside them may: drive roots, `C:\Users`, every profile, its `AppData`, `Local`, `LocalLow`, `Roaming`, `Local\Microsoft`, `Roaming\Microsoft`, `Local\Packages`, `Local\Programs`, and `C:\ProgramData`, `ProgramData\Microsoft`, `ProgramData\Microsoft\Windows`.
- Anything not on a local fixed drive.

Protected names match ignoring case in every script; exceptions match ignoring ASCII case only, so a doubtful spelling is refused. Fuzzing checks that every spelling Windows treats as the same path gets the same answer.

### 5.3 The deleter

`internal/clean`, input `Spec{Folders, Files, Exclude, Include, MinAge, RemoveRoot}`:

1. **Check** each folder against the deny list, then **open** it as an `os.Root`, on a local fixed drive only, and ask Windows (`GetFinalPathNameByHandle`) where the opened folder really is. A junction or link on the way, a short (8.3) name or a SUBST drive gives another path, and the folder is refused.
2. **Confine**: every later listing and deletion names a path relative to that handle. Go's `os.Root` refuses any path through a junction or symbolic link, since their targets are absolute. So a folder swapped for a junction after the check can't lead the deleter elsewhere; a test does exactly that swap.
3. **Walk** deepest first, listing through the handle with the scanner's own decoder. Links, online-only files, excluded locations (what other findings cover inside the folder), files not matching `Include`, files changed within `MinAge` and anything the deny list protects are left alone. A file's age counts from the later of its creation and last change, since unpacked files keep old modification times.
4. **Delete** each file through the handle: read-only files too, a link itself (never its target), and only if Windows allows it: no restore privilege, so permissions apply. Files in use (sharing violation) or not allowed are skipped and reported.
5. **Tidy**: a folder emptied this way is removed if it is itself older than `MinAge`; the cleaned folder stays unless `RemoveRoot` (for leftovers like `C:\NVIDIA`).
6. **Dry run**: the same walk with nothing deleted. A property test on random trees checks that it reports exactly what the real run deletes. The only difference on a real PC: a dry run can't know which files are in use or not allowed to be deleted, so its estimate is an upper bound, and the preview says so.
7. **Re-check at run time**: the real run starts from the approved spec, not a frozen file list, so it repeats every check and picks up what changed since the preview.
8. **No `os.RemoveAll`**: its handling of junctions has changed between Go versions.

The test fuse (`safety.GuardDelete`) sits right before the system call, so a test can only ever delete inside its own sandboxes.

### 5.4 Command actions

- Only Windows' own tools from System32, with fixed arguments; the preview shows the exact command line.
- Run through `execx` inside a Job Object (stopping it stops the whole process tree), with a timeout, and the output passed on line by line into the cleanup's log; a carriage return ends a line too, and DISM's progress bar becomes a percentage.
- Tools run without a console of their own to share, so Ctrl+C typed in COptimizer's window can't reach them.
- DISM component cleanup: `dism.exe /Online /English /Cleanup-Image /StartComponentCleanup`. It takes minutes, can't be stopped once started, has no time limit for that reason, and exit code 3010 means "done, restart to finish". It shares one lock with DISM's analyses (section 7.3), since DISM refuses to run twice at once: whichever comes second waits.
- The Recycle Bin is emptied through the shell, which empties all of it; so just before, COptimizer asks again what it holds, and refuses if that changed since the preview (something deleted meanwhile would otherwise be destroyed unseen).
- Delivery Optimization: `powershell.exe -NoProfile -NonInteractive -Command "Invoke-CimMethod … MSFT_DeliveryOptimizationFile -MethodName Delete …"`, the same call `Delete-DeliveryOptimizationCache` makes, without loading that command's script module (a restrictive execution policy would block it). Pinned files stay.
- Locale-proof: `DISM /English`; the registry instead of `powercfg` text. Translated text is never parsed.

### 5.5 Disk Cleanup adapter (phase 4)

Enumerates the handlers under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches` at runtime, since they differ between Windows versions. It sets `StateFlags0731` = 2 on the chosen ones, runs `cleanmgr /sagerun:731`, then removes those values again. It covers what raw deletion can't do well: Previous Windows installation(s), Temporary Windows installation files, upgrade logs, Device driver packages, and thumbnails (Explorer holds its thumbnail cache open). If a future Windows drops `cleanmgr`, those actions fall back to direct methods or guidance.

## 6. Scan engine

- **Enumerator** (`winfs`): opens each folder with `FILE_FLAG_BACKUP_SEMANTICS` and reads it in 64 KB batches with `GetFileInformationByHandleEx(FileIdBothDirectoryInfo)`. Every entry brings name, attributes, size, allocated size, file ID, last-write time and reparse tag, so no file is ever opened. With `SeBackupPrivilege` enabled it can measure folders that even Administrators can't list (`System Volume Information`, `WindowsApps`).
- **Parallel walk**: a worker pool, by default 2 × CPU cores; fewer on spinning disks, detected through `IOCTL_STORAGE_QUERY_PROPERTY` (seek penalty).
- **What's kept in memory**: a tree of folders only (name, parent, size, size on disk, file and folder counts, newest change, flags), the 1,000 largest files (a heap), totals per file type, and access-denied paths.
- **Correctness**:
  - Reparse points are recorded but never followed: no loops, no double counting (`C:\Users\All Users`).
  - Hard links count once: a set of file IDs (a few tens of MB per million files) marks repeats as shared. This matters for `WinSxS` and pnpm stores.
  - Cloud placeholders (online-only OneDrive files) are counted by allocated size, about 0, and never opened, since opening one downloads it. Listing an online-only folder can fetch its file list from the cloud, never file contents.
  - Both size and size on disk are reported; compressed and sparse files are handled through the allocated size.
- **Unaccounted space**: used space (from `GetDiskFreeSpaceEx`) minus what the scan counted. A big gap usually means shadow copies or file-system metadata, and the UI says so.
- **Modes**: Full (the whole drive) and, after a cleanup, a measurement of the cleaned folders only, merged into a copy of the scan (`scan.Refresh`) so the findings update in seconds. A file hard-linked from outside such a folder counts in full there, so WinSxS is never measured this way: after DISM's cleanup, a new full scan shows its size. Quick scans (rule folders and probes only) come in phase 4. Scans cover C: unless the user adds other fixed drives.
- **Progress** every 250 ms: folders, files, bytes, current path, errors, elapsed time. Percentage = counted bytes ÷ used bytes, held at 99% until done.
- **Snapshots**: after a full scan, folders of 50 MB or more and their sizes are saved to `data\snapshots.json.gz` (the last 10 per drive). Two snapshots give "what grew".
- **Targets**: at least 50,000 entries per second on an SSD; under 300 MB of memory for 2 million files; the UI stays responsive throughout.
- **Later**: read the NTFS master file table directly, as WizTree does, for much faster scans.

## 7. Rules

### 7.1 Model

As built in phase 2 (`internal/rules`):

```go
type Rule struct {
    ID         string   // "dev.npm-cache"; its texts are rule.<ID>.title/.what/.how in web/i18n/rules.en.json
    Category   Category // system, updates, drivers, virtual, dev, ai, browsers, apps, media, games, personal, other
    Risk       Risk     // safe | moderate | manual | info (explains space; nothing to reclaim)
    Folders    []string // patterns such as `{LocalAppData}\npm-cache`; * and ? allowed in a name
    Files      []string // patterns looked up among the scan's largest files, e.g. `{LocalAppData}\wsl\*\ext4.vhdx`
    Min        int64    // report the finding only from this total size on
    ItemMin    int64    // list a single location only from this size on
    Unreadable bool     // report the folder even when it couldn't be read (restore points)
    // plus, for the few rules patterns can't express, a detector function
}
```

Rules only look at the finished scan; they never read the disk themselves. Every location counts for one finding at most: the most specific pattern claims it first (deeper patterns, then those with fewer wildcards), and a broader pattern that covers it later only counts what is left. `Temp\SymbolCache` goes to the Visual Studio rule, the rest of `Temp` to the temp rule, and the findings add up without counting anything twice. Detectors run before the patterns (`node_modules` folders) or after them (other user accounts, huge log files, big files, unexplained folders, growth).

Phase 3 added the actions, as built:

```go
type Action struct {
    Kind        ActionKind    // Delete | EmptyRecycleBin | ComponentCleanup | DeliveryOptimization
    Folders     []string      // Delete: which of the rule's folders it cleans; nil: all
    Include     []string      // Delete: only files whose names match, e.g. "*.log"
    MinAge      time.Duration // Delete: leave what changed more recently (temp folders: a day)
    RemoveRoot  bool          // Delete: remove the folders themselves too (leftovers like C:\NVIDIA)
    NeedsClosed []string      // programs that must not be running, e.g. "chrome.exe"
    Long        bool          // takes minutes and can't be stopped once started (DISM)
}
```

34 rules have one: 31 Safe-tier deletions, the Recycle Bin, Delivery Optimization and DISM's component cleanup (on the Info-tier component store finding). Deliberately without an action: the Office file cache (it can hold documents not yet uploaded), Maven's repository (JARs installed by hand), pnpm's package store and conda's packages (only their own tools know what is unused), thumbnails (Explorer holds them open), stale Steam downloads, the Windows Update download cache and the print queue (both need services stopped: phase 4).

The catalog is plain Go (`rules/catalog.go`, 84 rules), following space-hogs.md section by section. The texts the page shows live in `web/i18n/rules.en.json`, so translating the findings is one file; a test checks that every rule has its texts and that no text is left over.

### 7.2 Per-user rules

Per-user rules run for every real profile in `C:\Users`, skipping `Default`, `Public`, `All Users`, `Default User` and links. That finds other accounts' caches too, and means an elevated account switch can't point us at the wrong folders. Cleanups touch only the profile of the account COptimizer runs as; the others are listed in the preview as left alone.

### 7.3 Probes

All read-only, each with a time limit (`internal/probe`).

| Probe | Source | Status |
|---|---|---|
| Drives and free space | `GetDiskFreeSpaceEx` | phase 1 |
| Hibernation and page files | Registry `HibernateEnabled`, `ExistingPageFiles`, `PagingFiles`; file sizes | phase 2 |
| WSL | Registry `HKCU\…\Lxss` (each distribution's name and disk), without starting WSL | phase 2 |
| Reserved storage | `dism.exe /Online /English /Get-ReservedStorageState` (needs admin) | phase 2 |
| Component store | `dism.exe /Online /English /Cleanup-Image /AnalyzeComponentStore` (needs admin; minutes, so only when the user clicks Analyze) | phase 2 |
| Restore points | Measured by the scan itself: `System Volume Information`, readable with Administrator rights | phase 2 |
| Recycle Bin | Measured by the scan itself: `$Recycle.Bin` | phase 2 |
| Restore point limit | `vssadmin` or CIM `Win32_ShadowStorage` | phase 4, with the restore-point actions |
| Recycle Bin, your own | `SHQueryRecycleBin` for the drive (size and items), for the preview | phase 3 |
| Running programs | Toolhelp32 snapshot of process names, for the programs a cleanup needs closed | phase 3 |
| Personal folders | Registry `User Shell Folders` and the `OneDrive` variables, for the deny list | phase 3 |
| Docker images and build cache | `docker system df`, run as the signed-in user through the unelevated helper | phase 4 |
| Installed programs | Uninstall registry keys (names, `EstimatedSize`) | later (leftover detection) |
| Windows upgrade in progress | Setup processes, recent activity in `$Windows.~BT` | phase 4 |

**Never run user tools elevated.** The server runs as Administrator, and tools installed in folders the user can write to (`docker`, `npm`, `wsl`, everything under `AppData` or on the user PATH) could have been replaced by malware, which would then run with Administrator rights. Probes and cleanups therefore only start Windows' own tools from System32 (with System32 as the working folder). From phase 4, commands of user tools run as the signed-in user, through the unelevated helper, never from the elevated server.

### 7.4 Smart findings beyond the catalog

- **Unrecognized big folders** (built): folders holding 1 GB or more that no finding explains, reported as deep in the tree as possible, never general folders like a profile or AppData themselves. Flagged "looks like a cache" when the name says so (cache, temp, tmp, log, crash, dump, shader). Your decision.
- **Growth** (built): folders that grew by 512 MB or more since the previous scan of the same drive taken with the same rights (with and without Administrator rights the scan sees different folders). Snapshots keep folders of 50 MB or more, the last 10 per drive, in `data\snapshots.json.gz`.
- **Big files** (built): files of 1 GB or more outside Windows, Program Files and ProgramData that no other finding covers; **huge logs**: `.log` and `.etl` files of 500 MB or more.
- **Other accounts and `node_modules`** (built): other users' profiles beyond their caches; `node_modules` folders of projects.
- **Leftovers** (later): AppData and ProgramData folders that match no installed program.
- **Duplicates** (phase 5): big files grouped by size, then by partial hash, then by full hash.
- **Ranking**: by reclaimable size. "Quick wins" shows Safe items first, and the header shows totals per tier.
- **Relocation advice**: when another drive has room, exact steps to move caches, WSL, Docker, the page file and user folders there.

## 8. Plans and jobs

```
POST /api/plans {ruleId}  → a preview, worked out by a dry run that changes nothing:
     id, bytes and files it would delete, each location with what the dry run found
     and a few sample names, the locations left alone and why (another account,
     needs Administrator rights, needs its own tool), the exact command line,
     programs to close, whether it can run now; expires in 10 minutes
POST /api/jobs  {planId}  → a cleanup: queued → running → succeeded | partial | failed | cancelled
     events: job.queued, job.started, job.progress, job.log, job.finished
afterwards: free space measured, history.jsonl appended, the cleaned folders
            measured again and the findings updated (scan.updated)
```

- A preview approves a *spec* (rule, folders, filters), not a frozen file list. The run checks everything again (Administrator rights, programs to close, the deny list, every folder's real path) and enumerates afresh, so temp files created since the preview are included and anything that turned into a link is skipped. A preview can be used once.
- Cleanups run one at a time from a queue; scans and probes can run alongside them. Stopping works through context cancellation and Job Objects, for deletions; emptying the Recycle Bin, DISM and Delivery Optimization can't be stopped half-way, so their cleanups offer no Stop. Quitting while a cleanup runs needs a second request (section 5.1).
- Freed space is measured (free bytes before and after) and shown next to the estimate.
- Simulation mode makes every cleanup a dry run; its history entries are marked as simulations.

## 9. HTTP API

| Method and path | Purpose |
|---|---|
| `GET /healthz` | Liveness check for the launcher; no data, no auth |
| `POST /api/session` | Exchange the one-time launch code for a session token |
| `GET /api/status` | Version, elevation, signed-in user, simulation mode, busy state |
| `GET /api/drives` | Drives with size, used and free space |
| `POST /api/scans` | Start a full scan of whole drives `{drives: ["C:\\"]}` |
| `GET /api/scans/{id}` | Scan state, progress, summary |
| `DELETE /api/scans/{id}` | Cancel a scan |
| `GET /api/scans/{id}/tree?path=…` | Children of a folder with sizes (lazy tree) |
| `GET /api/scans/{id}/files?limit=…` | Largest files |
| `GET /api/scans/{id}/types` | Totals by file type |
| `GET /api/scans/{id}/findings` | The scan's findings, largest first, with totals per risk and the date growth is compared with |
| `GET /api/system` | The latest result of every probe |
| `POST /api/system/{name}` | Run a probe now (the component store analysis runs only this way) |
| `POST /api/plans` | Preview the cleanup of a finding of the latest scan `{ruleId}` (dry run) |
| `POST /api/jobs` | Run a preview `{planId}` |
| `GET /api/jobs`, `GET /api/jobs/{id}` | This session's cleanups; one with its log and every location's outcome |
| `DELETE /api/jobs/{id}` | Stop a cleanup, or take it out of the queue |
| `GET /api/history` | Past cleanups, newest first, with what each freed |
| `GET /api/config`, `PUT /api/config` | Settings: simulation mode `{simulate}` |
| `POST /api/reveal` | Open Explorer at a path the scan found (later) |
| `GET /api/events` | Event stream |
| `POST /api/shutdown` | Stop the server |

Errors look like `{"error": {"code": "plan_expired", "message": "…"}}`, with status 400, 401, 403, 404, 409 (busy, a stale or used preview, programs to close, Administrator rights needed), 421 (wrong Host) or 500.

Events: `hello` (carrying the ID of the last event so far, to resume from), `heartbeat` (every 15 s), `scan.started`, `scan.progress` (not kept for replay), `scan.finished` (findings ready), `scan.updated` (folders measured again after a cleanup), `system.updated` (a probe's new result), `job.queued`, `job.started`, `job.progress` and `job.log` (not kept for replay), `job.finished`, `config.updated`. Each carries an ID; after a reconnect the client sends `Last-Event-ID` and the server replays from a 1,000-event buffer. On every `hello` the page also loads the cleanups and system information afresh.

## 10. Web client

| Page | Contents |
|---|---|
| Overview | Drive gauges (C: large, others small); Quick scan and Full scan buttons; live progress; "Reclaimable: X GB safe · Y GB with trade-offs · Z GB for you to decide"; top 5 quick wins |
| Findings | Cards by category, filterable by tier, sorted by size. Each card shows size, tier, what it is and what cleaning costs, where, and, when COptimizer can clean it, a button that opens the preview: the exact folders or command, what is left alone, programs to close, then confirm, live progress and the measured result |
| Explorer | Lazy folder tree with size bars and % of parent, breadcrumb, largest files, file types; a treemap later |
| Activity | Simulation mode; this session's cleanups with live progress; the history with freed totals |
| Settings | Later: scan threads, exclusions, thresholds (big file, unrecognized folder, temp-file age), language |

UX rules: nothing runs without a click on a preview, and the preview shows exactly what will happen. Conflicting buttons are disabled while a job runs. A connection indicator is always visible. Keyboard accessible, with light and dark themes.

Files: `web/index.html`, `web/css/app.css`, and `web/js/` with `main.js`, `api.js` (fetch, auth, errors), `events.js` (event stream over fetch, auto-reconnect), `store.js` (a small store), `format.js`, `i18n.js`, `dom.js` and `views/*.js` (overview, findings, explorer, activity, and the cleanup dialog).

## 11. Data and configuration

`<exe folder>\data\` (or `-data-dir`) holds `snapshots.json.gz` (earlier scans, for growth) and `history.jsonl` (the append-only record of cleanups). Planned: `config.json`, and logs in `logs\coptimizer-YYYYMMDD.log` (7 days kept).

Flags: `-serve`, `-demo`, `-port`, `-launch-code`, `-instance`, `-no-browser`, `-data-dir`, `-simulate`, `-version`. Planned: `-log-level`.

**Demo mode** (`--demo`) wires the in-memory filesystem, the fake system and the fake command runner, loaded with a synthetic machine modelled on the manual scan in space-hogs.md (section 5). Its cleanups delete from the in-memory drive, whose free space grows accordingly; its VS Code "runs" until a preview asks for it to be closed. It needs no admin rights and touches nothing real. It's used for UI work, UI tests and screenshots.

## 12. Repository layout

```
coptimizer\
├─ .github\workflows\ ci.yml: tests and build on a GitHub-hosted Windows runner
├─ cmd\coptimizer\    main.go: flags, launcher, wiring
├─ internal\          server, scan, winfs, fsx, rules, probe, actions, clean,
│                     safety, execx, sysinfo, store, demo, testguard, sandbox
├─ web\               index.html, css\, js\  (embedded into the exe)
├─ testdata\          parser fixtures, demo machine
├─ e2e\               optional Playwright UI tests (demo mode)
├─ scripts\           dev.ps1, build.ps1, test.ps1, destructive.ps1
├─ docs\              plan.md, space-hogs.md, testing.md
├─ go.mod, LICENSE (MIT), SECURITY.md
└─ README.md
```

`.gitignore`: `data/`, `dist/`, `.tmp/`, `e2e/node_modules/`.

## 13. Build and run

- **Prerequisites**: Go at the version in `go.mod`. If C: is small, keep Go and its caches on another drive, e.g. the official zip unpacked to `D:\dev\go` plus `go env -w GOPATH=D:\dev\gopath GOCACHE=D:\dev\gocache`. Node.js only for the optional UI tests.
- `scripts\dev.ps1`: `go run ./cmd/coptimizer --demo`, for UI work without admin rights or real effects.
- `scripts\build.ps1`: `go build -trimpath -ldflags "-s -w -X main.version=<git describe>" -o dist\coptimizer.exe ./cmd/coptimizer`.
- `scripts\test.ps1` and `scripts\destructive.ps1` (disposable machines only): see testing.md.
- **Release**: `coptimizer.exe` plus its SHA-256. Code signing later, to avoid SmartScreen warnings and antivirus suspicion; version info and icon via `go-winres`.

## 14. Phases

Each phase ends with its tests passing, its manual checks done and a short demo.

| Phase | Builds | Done when |
|---|---|---|
| 0. Scaffold ✅ | Layout, `go.mod`, scripts, `.gitignore`, README, MIT `LICENSE`, `SECURITY.md`, CI workflow. **First**, so every later test is protected from day one: the `safety` fuses, the `sandbox` test helpers, `testguard` and the forbidden-API test | `scripts\test.ps1` runs green and refuses to run elevated; planted violations and a weakened fuse make the tests fail (met 24 Oct 2026) |
| 1. Read-only core ✅ | `winfs` enumerator, scanner, drives probe, server (auth, Host and Origin checks, events), launcher and elevation, UI Overview + Explorer + progress, demo mode, browser tests | A full scan of C: works; folder totals match Explorer within ~1%; ~1M files take under 2 minutes; the codebase has no code yet that deletes files or changes settings. Measured 24 Oct 2026 on a 120 GB budget SATA SSD, without admin rights: 730k files and 185k folders in 104 s cold and 20 s warm; `Program Files` within 0.006% of PowerShell's count, same number of files. The elevated launch (UAC) still needs its first manual run |
| 2. Findings ✅ | Rule engine (84 rules) with per-user expansion and specific-before-general claiming; detectors for `node_modules`, other accounts, big files, huge logs, unexplained folders and growth; scan snapshots; deterministic hard-link counting; probes (power, WSL, reserved storage, component store on demand) through a job-object command runner; Findings page and system information | On the author's PC the app finds, automatically, everything the manual scan in space-hogs.md (section 5) found. Met 24 Oct 2026: the demo PC built from that scan shows every finding (tested), and a real read-only scan of the author's C: found what is still there (Playwright 2.6 GB, Chrome caches in 46 profile folders, pnpm and npm caches, …); hibernation, the page file and WSL had meanwhile been moved off C:, which the probes confirm. Two scans minutes apart report no growth |
| 3. Safe actions (built) | Deny list; deleter confined to an `os.Root` handle, with dry runs; line-by-line output for the command runner; previews, a one-at-a-time cleanup queue, history and measuring the cleaned folders again; the cleanup dialog and the Activity page; simulation mode. Actions on 34 rules: temp folders, package-manager and developer caches, browser, editor and chat-app caches, shader caches, crash dumps, error reports and servicing logs, driver installer and update-assistant leftovers, Steam and Epic leftovers, the Recycle Bin, Delivery Optimization (its own CIM provider) and DISM `StartComponentCleanup` | Every action is covered by fake and sandbox tests (met: the deleter on real folders in sandboxes, including a folder swapped for a junction mid-run; the whole flow from preview to history through the API and in the browser; real cleanups with Administrator rights on a disposable CI runner). Previews checked read-only on the author's PC, 24 Oct 2026: estimates match the scan, Chrome and VS Code caches wait for those programs to close, temp offers only files older than a day, and pnpm's junctions into its store are left alone. Two independent reviews of the cleanup code found no way for it to reach anything outside an approved folder; their other findings (a preview made in simulation mode could run for real if the mode changed in another tab, Ctrl+C in the console reached DISM, a queued Recycle Bin cleanup emptied what was deleted after its preview, DISM's cleanup and analysis could run at once, …) were fixed, each with a test. Still to do: at least 5 real cleanups on the author's PC, preview first, with measured results matching the estimate |
| 4. Moderate actions | Hibernation (reduced, off, on), restore points (keep newest, cap size), upgrade leftovers (`$Windows.~BT`, `$Windows.~WS`, `Windows.old`) and thumbnails via the Disk Cleanup adapter, DISM `/ResetBase`, Compact OS, WSL sparse / compact / move, Docker prune (never volumes by default). The unelevated helper for user tools (`pnpm store prune`, `conda clean`, `docker system df`). Cleanups that need services stopped (Windows Update download cache, print queue). Quick scans. Acknowledgement dialogs with undo steps | Dry runs checked on a real PC; real runs only on a disposable VM or CI runner, or deliberately by the person at the PC |
| 5. Polish | Relocation advisor with one-click config changes (e.g. npm cache to D:), recycle selected personal files (an explicit per-file choice, sent to the Recycle Bin), duplicates, treemap, Vietnamese UI, packaging and signing | |
| Later | NTFS master-file-table scanner, scheduled scans with notifications, arm64 build | |

## 15. Risks and open questions

Risks:

- **Windows changes** (Disk Cleanup being retired, new folders appearing): handlers are read at runtime, the catalog is versioned, and every action has a fallback.
- **Antivirus suspicion** of an unsigned exe that elevates and deletes files: code signing, no packers, a clear README.
- **Long DISM and Disk Cleanup runs** that can't be cancelled: the UI warns before starting and shows elapsed time.
- **Memory for hard-link tracking on huge disks**: capped; past the cap, totals are marked approximate.
- **Non-English Windows**: designed in, since translated output is never parsed.
- **Programs run with Administrator rights**: only Windows' own tools from System32; user tools run as the signed-in user from phase 4 (section 7.3).
- **Junctions inside caches**: real caches contain them (pnpm's `dlx` folder links into its package store). The deleter never enters one and can't be led through one (section 5.3).
- **Cleanups that can't be stopped** (DISM): no Stop button and no time limit, and quitting needs a second request while one runs; closing COptimizer's window still ends DISM, which Windows tolerates, as it does when its own scheduled cleanup is interrupted.

Decisions made on 24 Oct 2026:

1. Server in Go; web page in plain HTML/JS.
2. Name: COptimizer. Interface in English first, translation-ready, with Vietnamese in phase 5.
3. Scans cover C: by default; other fixed drives on request.
4. Open source on GitHub from day one, under the MIT license.
5. Development toolchain: Go from the official zip, kept outside C:.
