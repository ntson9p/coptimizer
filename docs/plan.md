# COptimizer: implementation plan

Status: phase 0 done (project setup and the test safety fuses); phase 1 next. Companion documents: [space-hogs.md](space-hogs.md) (what the app looks for) and [testing.md](testing.md) (how it's tested without risking anyone's PC).

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

The launcher passes its own user SID. If the elevated account is a different one (a standard user typed an administrator's password), per-user tool actions (`npm`, `wsl`, `docker`) are disabled with an explanation, because they would run against the wrong account.

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
| `internal/rules` | Rule model, catalog (one file per category), probes, per-user expansion, smart findings |
| `internal/actions` | Plans (dry runs), safe deleter, command actions, Disk Cleanup and DISM adapters |
| `internal/safety` | Path normalization, allow and deny policy, test fuses |
| `internal/execx` | Command runner (Job Objects, timeouts, streaming, output decoding), plus a fake runner |
| `internal/sysinfo` | Drives, elevation, processes, registry, power, shadow copies, Recycle Bin. Split into `Reader` (read-only) and `Mutator` |
| `internal/jobs` | Job queue, state machine, progress events |
| `internal/store` | Config, `history.jsonl`, scan snapshots |
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
| Using the elevated API to delete or run arbitrary things | The API never accepts a path to delete or a command to run, only catalog IDs. "Reveal in Explorer" only takes paths the scan found. JSON decoding rejects unknown fields |
| Supply chain | Only Go-project modules; zero third-party UI code |
| Running tools | Arguments passed as arrays, never through a shell. Windows tools by absolute path (`%SystemRoot%\System32\dism.exe`). User tools (`npm`, `docker`) are resolved once and the full path is shown in the preview |
| Privileges | Enables `SeBackupPrivilege` to *measure* protected folders. Never enables `SeRestorePrivilege` or `SeTakeOwnershipPrivilege`, so file permissions still stop us deleting protected files |

## 5. Safety model

### 5.1 Golden rules, enforced in code

1. **The client never names what to delete.** Requests carry `{ruleId, actionId, planId}`; paths come from the catalog and are expanded on the server.
2. **Deletes happen only inside a rule's declared folders**, and never on the deny list (5.2), even if a rule asks.
3. **Use the owner's tool first**: `npm cache clean`, DISM, Disk Cleanup handlers, `Delete-DeliveryOptimizationCache`, `powercfg`, `vssadmin`. Raw deletion is only for plain caches and temp folders.
4. **Never follow reparse points** (junctions, symlinks, mount points, cloud placeholders). One found inside a cache folder is skipped, not entered.
5. **A preview always comes first.** Moderate actions also need a ticked acknowledgement that states the trade-off and how to undo it.
6. **Skip files that are in use; never kill processes.** If an app must be closed first (`chrome.exe` for its cache), the app asks you to close it.
7. **Fail closed.** Anything that can't be resolved or validated is skipped and reported.
8. **Measure the result.** Free space before and after, per-item totals, and an entry in `history.jsonl`.
9. **One changing action at a time.**
10. **Simulation mode**, a global switch, turns every action into a dry run.

### 5.2 Deny list

The generic deleter refuses these whatever a rule says. The list lives in one small file with its own tests.

- Drive roots (`C:\`).
- `C:\Windows`, except an explicit list: `Temp`, `SystemTemp`, `Logs\CBS` (`*.log`, `*.cab` only), `Minidump`, `MEMORY.DMP`, `LiveKernelReports`, `SoftwareDistribution\Download` (only with the update services stopped).
- `C:\Windows\WinSxS`, `C:\Windows\Installer`, `C:\Windows\System32`, `C:\Program Files`, `C:\Program Files (x86)`, `C:\ProgramData\Package Cache`, `C:\System Volume Information`.
- Each profile root `C:\Users\<name>`, and the user content folders: Desktop, Documents, Downloads, Pictures, Videos, Music, OneDrive, wherever Known Folder redirection points them.
- Anything not on a local fixed drive (network shares, removable media).

### 5.3 The deleter

Input: `DeleteSpec{Root, Mode (contents | folder | matching files), MinAge, Include, Exclude, KeepRoot}`.

1. **Normalize** the root: absolute path via `GetFullPathName`, short (8.3) names expanded, `\\?\` prefixes handled, compared case-insensitively.
2. **Validate**: local fixed drive, not a reparse point, not denied, inside the rule's allowed roots.
3. **Confine**: open it as an `os.Root` (Go 1.24+) and do every later operation through it, so Go's traversal-resistant file access keeps everything inside that folder even if our own path logic had a bug.
4. **Walk** with the same enumerator as the scanner. For each entry: skip reparse points and cloud placeholders, skip anything newer than `MinAge`, clear the read-only attribute, delete. Sharing violations and access-denied errors count as skipped.
5. **Tidy**: remove emptied folders bottom-up, except the root when `KeepRoot` is set.
6. **Dry run**: the same code with `dryRun=true`, so the preview comes from the same logic as the real run.
7. **Re-validate** the root at the start of the real run, since it may have changed after the preview.
8. **No `os.RemoveAll`** on trees: its handling of junctions has changed between Go versions and isn't what we want.

### 5.4 Command actions

- Defined as argument templates; the resolved command line is shown in the preview.
- Run through `execx` inside a Job Object (cancel kills the whole process tree), with a timeout, and stdout/stderr streamed line by line into the job log. Output is decoded from UTF-16, the console code page or UTF-8 as needed, and `\r` counts as a line break (DISM draws its progress bar with it).
- Locale-proof: `DISM /English`; CIM queries through `powershell.exe -NoProfile -NonInteractive -Command "… | ConvertTo-Json"`; the registry instead of `powercfg` text. Translated text is never parsed.
- Commands that can't be stopped safely (DISM component cleanup) get no Cancel button.

### 5.5 Disk Cleanup adapter

Enumerates the handlers under `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches` at runtime, since they differ between Windows versions. It sets `StateFlags0731` = 2 on the chosen ones, runs `cleanmgr /sagerun:731`, then removes those values again. This covers Windows Update Cleanup, Previous Windows installation(s), Temporary Windows installation files, upgrade logs, Device driver packages, Delivery Optimization files, memory dumps, thumbnails and the DirectX shader cache. If a future Windows drops `cleanmgr`, those actions fall back to direct methods or guidance.

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
- **Modes**: Quick (rule folders and probes only, seconds), Full (the whole drive), Folder (one subtree, used to refresh after an action). Scans cover C: unless the user adds other fixed drives.
- **Progress** every 250 ms: folders, files, bytes, current path, errors, elapsed time. Percentage = counted bytes ÷ used bytes, held at 99% until done.
- **Snapshots**: after a full scan, folders of 50 MB or more and their sizes are saved to `data\scans\<time>.json.gz` (last 10 kept). Two snapshots give "what grew".
- **Targets**: at least 50,000 entries per second on an SSD; under 300 MB of memory for 2 million files; the UI stays responsive throughout.
- **Later**: read the NTFS master file table directly, as WizTree does, for much faster scans.

## 7. Rules

### 7.1 Model

```go
type Rule struct {
    ID       string   // "dev.npm.cache"
    Category Category // System, Updates, Drivers, Virtual, Dev, AI, Browsers, Apps, Media, Games, Personal, Other
    Title    string
    Explain  string   // what it is, why it grows
    Effect   string   // what cleaning costs, how to undo it
    Prevent  string   // how to stop it coming back
    Risk     Risk     // Safe | Moderate | Manual
    Scope    Scope    // System | PerUser (expanded for every profile)
    Paths    []string // templates such as `{LocalAppData}\npm-cache`
    Probe    Probe    // optional read-only detector (registry, CIM, docker, DISM…)
    Actions  []ActionSpec
}

type ActionSpec struct {
    ID          string
    Label       string
    Kind        ActionKind // RunCommand | DeleteContents | DiskCleanup | Cmdlet | OpenSettings | Reveal | Guide
    Command     []string   // {"npm", "cache", "clean", "--force"}
    Delete      *DeleteSpec
    NeedsTool   string     // the action is hidden when the tool isn't installed
    NeedsClosed []string   // processes that must not be running, e.g. "chrome.exe"
    Confirm     Confirm    // Simple | Acknowledge
    Cancellable bool
}
```

The catalog is plain Go, one file per category (`rules/catalog_dev.go`, …), and each rule points at its entry in space-hogs.md. Because rules are code, every one is type-checked and unit-tested.

### 7.2 Per-user rules

Per-user rules run for every real profile in `C:\Users`, skipping `Default`, `Public`, `All Users`, `Default User` and links. That finds other accounts' caches too, and means an elevated account switch can't point us at the wrong folders. Tool commands (`npm`, `wsl`, `docker`) are offered only for the signed-in user (see 3.1).

### 7.3 Probes

All read-only, each with a timeout, run in parallel.

| Probe | Source |
|---|---|
| Drives and free space | `GetDiskFreeSpaceEx` |
| Hibernation and page file | Directory entries for `hiberfil.sys` and `pagefile.sys`; registry `HibernateEnabled`, `HiberFileType`, `PagingFiles` |
| Restore points | CIM `Win32_ShadowStorage` and `Win32_ShadowCopy`, as JSON |
| Component store | `DISM /English /Online /Cleanup-Image /AnalyzeComponentStore` (takes 1–3 minutes, so only on demand) |
| Reserved storage | `DISM /English /Online /Get-ReservedStorageState` |
| Recycle Bin | `SHQueryRecycleBinW` per drive |
| WSL | Registry `HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss` (each distro's folder), plus `wsl.exe --list --verbose` (UTF-16 output) |
| Docker | `docker system df --format "{{json .}}"` when Docker is running |
| Installed programs | Uninstall registry keys (names, `EstimatedSize`) |
| Running processes | Toolhelp32 snapshot |
| Windows upgrade in progress | Setup processes running, or recent activity in `$Windows.~BT`; if so, upgrade-leftover cleanup is blocked |

### 7.4 Smart findings beyond the catalog

- **Unrecognized big folders**: anything of 1 GB or more (configurable) that no rule covers. It's flagged "looks like a cache" when its name says so (`cache`, `temp`, `logs`, `CrashDumps`, `GPUCache`, `Code Cache`, `shadercache`). Always Manual.
- **Growth**: "grew 5.2 GB since 10 Oct", from snapshot diffs.
- **Big files**: 500 MB or more outside system folders; installers, ISOs and archives in Downloads older than 30 days.
- **Leftovers**: AppData and ProgramData folders that match no installed program.
- **Duplicates** (phase 5): big files grouped by size, then by partial hash, then by full hash.
- **Ranking**: by reclaimable size. "Quick wins" shows Safe items first, and the header shows totals per tier.
- **Relocation advice**: when another drive has room, exact steps to move caches, WSL, Docker, the page file and user folders there.

## 8. Plans and jobs

```
POST /api/plans {ruleId, actionId}     → plan: a dry run that changes nothing
     planId, estimated items and bytes, sample paths, exact command line,
     warnings, apps to close, confirmation level, expires in 10 minutes
POST /api/jobs  {planId, acknowledged} → job: queued → running → succeeded | partial | failed | cancelled
     events: job.started, job.progress, job.log,
             job.finished {freed (measured), deleted, skipped, errors}
afterwards: the affected folder is re-scanned and its finding updated
```

- A plan approves a *spec* (rule, action, folders, filters), not a frozen file list. The run re-validates and re-enumerates, so temp files created since the preview are included, and anything that turned into a link is skipped.
- Jobs run one at a time from a queue; scans and probes can run alongside them. Cancel works through context cancellation and Job Objects.
- Freed space is measured (free bytes before and after) and shown next to the estimate.

## 9. HTTP API

| Method and path | Purpose |
|---|---|
| `GET /healthz` | Liveness check for the launcher; no data, no auth |
| `POST /api/session` | Exchange the one-time launch code for a session token |
| `GET /api/status` | Version, elevation, signed-in user, simulation mode, busy state |
| `GET /api/drives` | Drives with size, used and free space |
| `POST /api/scans` | Start a scan `{mode: quick \| full \| folder, drive, path?}` |
| `GET /api/scans/{id}` | Scan state, progress, summary |
| `DELETE /api/scans/{id}` | Cancel a scan |
| `GET /api/scans/{id}/tree?path=…` | Children of a folder with sizes (lazy tree) |
| `GET /api/scans/{id}/files?limit=…` | Largest files |
| `GET /api/scans/{id}/types` | Totals by file type |
| `GET /api/findings` | Findings by category, with tiers and available actions |
| `POST /api/findings/{id}/probe` | Run a slow probe on demand (component store analysis) |
| `POST /api/plans` | Create a plan (dry run) |
| `POST /api/jobs` | Run an approved plan |
| `GET /api/jobs`, `GET /api/jobs/{id}` | Jobs and their logs |
| `DELETE /api/jobs/{id}` | Cancel a job, when cancellable |
| `POST /api/reveal` | Open Explorer at a path the scan found |
| `GET /api/history` | Past actions and freed totals |
| `GET /api/config`, `PUT /api/config` | Settings |
| `GET /api/events` | Event stream |
| `POST /api/shutdown` | Stop the server |

Errors look like `{"error": {"code": "plan_expired", "message": "…"}}`, with status 400, 401, 403, 404, 409 (busy or stale plan), 421 (wrong Host) or 500.

Events: `hello`, `heartbeat` (every 15 s), `scan.progress`, `scan.finished`, `findings.updated`, `job.queued`, `job.started`, `job.progress`, `job.log`, `job.finished`, `drives.updated`. Each carries an ID; after a reconnect the client sends `Last-Event-ID` and the server replays from a 1,000-event buffer.

## 10. Web client

| Page | Contents |
|---|---|
| Overview | Drive gauges (C: large, others small); Quick scan and Full scan buttons; live progress; "Reclaimable: X GB safe · Y GB with trade-offs · Z GB for you to decide"; top 5 quick wins |
| Findings | Cards by category, filterable by tier, sorted by size. Each card shows size, tier, what it is and what cleaning costs, plus its actions: Preview (opens the plan with the exact folders or command, and a confirm button) and Reveal |
| Explorer | Lazy folder tree with size bars and % of parent, breadcrumb, largest files, file types; a treemap later |
| Activity | The running job with live log and progress; history with freed totals; export |
| Settings | Simulation mode, scan threads, exclusions, thresholds (big file, unrecognized folder, temp-file age), language |

UX rules: nothing runs without a click on a preview, and the preview shows exactly what will happen. Conflicting buttons are disabled while a job runs. A connection indicator is always visible. Keyboard accessible, with light and dark themes.

Files: `web/index.html`, `web/css/app.css`, and `web/js/` with `main.js`, `api.js` (fetch, auth, errors), `events.js` (event stream over fetch, auto-reconnect), `state.js` (a small store), `format.js`, `views/*.js` and `components/*.js` (gauge, progress, modal, tree, table, toast).

## 11. Data and configuration

`<exe folder>\data\` holds `config.json`, `history.jsonl` (append-only audit log), `scans\*.json.gz` and `logs\coptimizer-YYYYMMDD.log` (7 days kept). If the exe folder isn't writable, it falls back to `%LOCALAPPDATA%\COptimizer`.

Flags: `--serve`, `--port`, `--launch-code`, `--user-sid`, `--no-browser`, `--demo`, `--simulate`, `--data-dir`, `--log-level`.

**Demo mode** (`--demo`) wires the in-memory filesystem, the fake system and the fake command runner, loaded with a synthetic machine modelled on the manual scan in space-hogs.md (section 5). It needs no admin rights and touches nothing real. It's used for UI work, UI tests and screenshots.

## 12. Repository layout

```
coptimizer\
├─ .github\workflows\ ci.yml: tests and build on a GitHub-hosted Windows runner
├─ cmd\coptimizer\    main.go: flags, launcher, wiring
├─ internal\          server, scan, winfs, fsx, rules, actions, safety,
│                     execx, sysinfo, jobs, store, testguard, sandbox
├─ web\               index.html, css\, js\  (embedded into the exe)
├─ testdata\          parser fixtures, demo machine
├─ e2e\               optional Playwright UI tests (demo mode)
├─ scripts\           dev.ps1, build.ps1, test.ps1
├─ docs\              plan.md, space-hogs.md, testing.md
├─ go.mod, LICENSE (MIT), SECURITY.md
└─ README.md
```

`.gitignore`: `data/`, `dist/`, `.tmp/`, `e2e/node_modules/`.

## 13. Build and run

- **Prerequisites**: Go at the version in `go.mod`. If C: is small, keep Go and its caches on another drive, e.g. the official zip unpacked to `D:\dev\go` plus `go env -w GOPATH=D:\dev\gopath GOCACHE=D:\dev\gocache`. Node.js only for the optional UI tests.
- `scripts\dev.ps1`: `go run ./cmd/coptimizer --demo`, for UI work without admin rights or real effects.
- `scripts\build.ps1`: `go build -trimpath -ldflags "-s -w -X main.version=<git describe>" -o dist\coptimizer.exe ./cmd/coptimizer`.
- `scripts\test.ps1`: see testing.md.
- **Release**: `coptimizer.exe` plus its SHA-256. Code signing later, to avoid SmartScreen warnings and antivirus suspicion; version info and icon via `go-winres`.

## 14. Phases

Each phase ends with its tests passing, its manual checks done and a short demo.

| Phase | Builds | Done when |
|---|---|---|
| 0. Scaffold ✅ | Layout, `go.mod`, scripts, `.gitignore`, README, MIT `LICENSE`, `SECURITY.md`, CI workflow. **First**, so every later test is protected from day one: the `safety` fuses, the `sandbox` test helpers, `testguard` and the forbidden-API test | `scripts\test.ps1` runs green and refuses to run elevated; planted violations and a weakened fuse make the tests fail (met 24 Oct 2026) |
| 1. Read-only core | `winfs` enumerator, scanner, drives probe, server (auth, Host and Origin checks, events), launcher and elevation, UI Overview + Explorer + progress, demo mode | A full scan of C: works; folder totals match Explorer within ~1%; ~1M files take under 2 minutes; the codebase has no code yet that deletes files or changes settings |
| 2. Findings | Rule engine, per-user expansion, probes (power, restore points, Recycle Bin, WSL, Docker, DISM on demand, reserved storage), detection for every category in space-hogs.md, unrecognized folders, snapshots and growth, Findings UI | On the author's PC the app finds, automatically, everything the manual scan in space-hogs.md (section 5) found |
| 3. Safe actions | Safety policy, deleter (dry run and real), command runner, plans, jobs and history, Activity UI. Safe-tier actions: temp folders, Recycle Bin, package-manager caches, browser and Electron caches, shader caches, crash dumps and error reports, Delivery Optimization, Windows Update cleanup via Disk Cleanup, DISM StartComponentCleanup | Every action is covered by fake and sandbox tests; at least 5 have run for real on the author's PC, preview first, with measured results matching the estimate |
| 4. Moderate actions | Hibernation (reduced, off, on), restore points (keep newest, cap size), upgrade leftovers (`$GetCurrent`, `$Windows.~BT`, `$Windows.~WS`, `Windows.old` via Disk Cleanup), DISM `/ResetBase`, Compact OS, WSL sparse / compact / move, Docker prune (never volumes by default). Acknowledgement dialogs with undo steps | Dry runs checked on a real PC; real runs only on a disposable VM or CI runner, or deliberately by the person at the PC |
| 5. Polish | Relocation advisor with one-click config changes (e.g. npm cache to D:), recycle selected personal files (an explicit per-file choice, sent to the Recycle Bin), duplicates, treemap, Vietnamese UI, packaging and signing | |
| Later | NTFS master-file-table scanner, scheduled scans with notifications, arm64 build | |

## 15. Risks and open questions

Risks:

- **Windows changes** (Disk Cleanup being retired, new folders appearing): handlers are read at runtime, the catalog is versioned, and every action has a fallback.
- **Antivirus suspicion** of an unsigned exe that elevates and deletes files: code signing, no packers, a clear README.
- **Long DISM and Disk Cleanup runs** that can't be cancelled: the UI warns before starting and shows elapsed time.
- **Memory for hard-link tracking on huge disks**: capped; past the cap, totals are marked approximate.
- **Non-English Windows**: designed in, since translated output is never parsed.

Decisions made on 24 Oct 2026:

1. Server in Go; web page in plain HTML/JS.
2. Name: COptimizer. Interface in English first, translation-ready, with Vietnamese in phase 5.
3. Scans cover C: by default; other fixed drives on request.
4. Open source on GitHub from day one, under the MIT license.
5. Development toolchain: Go from the official zip, kept outside C:.
