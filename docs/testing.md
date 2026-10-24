# COptimizer: testing strategy

## Principle

Run real tests, but build them so they **cannot** touch anything outside throwaway folders. Reviewing the code in your head is not enough.

The riskiest code in this app deletes files and runs system tools as Administrator. If it were only reviewed, its first real run would happen as Administrator on someone's PC: the worst place to find a bug such as a path check that treats `C:\Temp2` as inside `C:\Temp`, or a junction that leads into Documents. Running that code thousands of times against fake and sandboxed folders is far safer than never running it before release. The real danger is a *test* touching real data, and that can be ruled out by construction.

## 1. Six independent protections

1. **Design**: every side effect goes through an interface: the filesystem (`fsx`), the command runner (`execx`), the system (`sysinfo.Reader` and `sysinfo.Mutator`). Core logic is tested with in-memory fakes; the real implementations are kept thin.
2. **Forbidden-API test**: `internal/safety/forbidden_test.go` parses every Go file in the repository, production and test code alike. Only a short, reviewed list of files may import `os/exec`, `syscall`, `unsafe` or `golang.org/x/sys/...`, or call the `os` functions that create, change or delete files or start programs. A second check makes every package with tests start them through `testguard`.
3. **Sandboxes**: a test that needs a real filesystem gets one from `sandbox.New(t)`: a fresh folder (under `<repo>\.tmp\` when run through `scripts\test.ps1`) that's deleted afterwards. The `sandbox` helpers are the only test code allowed to create files.
4. **Fuses in the production code**: inside a test binary (`testing.Testing()` is true):
   - `GuardWrite` and `GuardDelete` panic unless the path is inside a registered sandbox, both as written and after Windows itself (`GetFinalPathNameByHandle`) has followed every junction and link on the way;
   - `GuardRun` panics for any program except registered test helpers;
   - `GuardSystemChange` (registry, power options, restore points, Recycle Bin…) panics unconditionally.

   A forgotten fake therefore crashes the test instead of changing the PC.
5. **No admin**: `scripts\test.ps1` and the shared `testguard` `TestMain` refuse to run elevated, so Windows permissions would still block changes to system folders even if everything above failed. They would not protect the user's own files (Documents, Desktop), which a normal process can write; protections 2–4 cover those. The only exceptions are GitHub-hosted CI runners (disposable VMs) and `-Smoke -Elevated`.
6. **Real actions only on disposable machines**: tests that really clean Windows folders run only on a throwaway VM or CI runner, behind two independent checks (section 5).

The protections are tested themselves. A planted forbidden call, or a test package that skips `testguard`, makes the suite fail. A fuse weakened to skip the link check makes the junction tests fail. Go fuzzing checks the path rules against generated input.

The read-only smoke tests (section 4) only ever receive `sysinfo.Reader`, so the compiler stops them calling a mutator.

## 2. Test levels

| Level | When | What it touches | Covers |
|---|---|---|---|
| L1 Unit | every run | nothing | Path policy, rules, parsers, formatting, plans, API auth |
| L2 Fakes | every run | memory only | Scanner totals, deleter decisions, rule detection, job manager, actions with the fake runner |
| L3 Sandbox | every run | `.tmp` sandboxes only | Real Windows enumeration and deletion, junctions, locked and read-only files, long paths |
| L4 API / UI | every run (API), on demand (UI) | memory (demo mode) | HTTP and event contract; Playwright flows against `--demo` |
| L5 Smoke | on demand (`-Smoke`) | reads the real system | Enumeration of the real C:, probes |
| L6 Destructive | disposable VM or CI only | the throwaway machine | Real actions on real Windows folders |

## 3. Key test cases

### Path policy (table tests and Go fuzzing)

- `C:\Temp` vs `C:\Temp2`, and `C:\Temp\..\Windows`
- Case: `c:\TEMP\x`. Separators: `C:/Temp/x`, doubled `\\`
- Trailing dot or space: `C:\Temp.` and `C:\Temp ` (Windows treats both as `C:\Temp`)
- Short names: `C:\PROGRA~1` must be recognized as `C:\Program Files` and refused
- Prefixes: `\\?\C:\…`, `\\.\C:\…`, `\\?\GLOBALROOT\Device\…`, `\\?\Volume{GUID}\…`
- Network and relative paths: `\\server\share`, mapped network drives, `C:foo`, `.\foo` (all refused)
- Alternate data streams: `C:\Temp\a.txt:hidden`, `…::$DATA` (refused)
- Reserved names: `CON`, `NUL`, `COM1`, `aux.txt`
- Very long paths (over 260 and over 32,767 characters); Vietnamese and other Unicode names, with NFC and NFD forms kept distinct
- Every deny-list folder, plus its case, short-name and prefix variants
- Fuzz invariant: if a path is allowed, its canonical form lies strictly inside the canonical root and is not denied; the check never panics

### Deleter (L2 and L3)

- A junction inside a cache folder pointing at a **canary** folder outside it: the canary is untouched (a real `mklink /J`, which needs no admin)
- Symlinks: tested when Developer Mode allows creating them, otherwise skipped with a message
- The root itself is a junction: refused
- Folder swapped for a junction between preview and run: refused at run time
- Read-only, hidden and system attributes: deleted after clearing read-only
- A file the test holds open without delete sharing: skipped and reported; the job ends as `partial`
- A folder with a deny entry for the current user (set by the test on its own sandbox): skipped
- `MinAge` boundaries, include and exclude patterns, `KeepRoot`
- Cancel half-way: counts stay consistent
- Dry-run parity (a property test on random trees): the dry run lists exactly what the real run deletes
- Cloud placeholder attribute (fake FS): never opened, skipped
- A 100,000-file folder: time stays reasonable

### Scanner

- Fake FS: totals and counts for deep and wide trees; reparse points not followed; hard links (same file ID) counted once; placeholders count 0 on disk; access-denied entries counted; cancel
- L3: totals for a generated sandbox tree agree with an independent `filepath.WalkDir` + `Lstat` computation
- Progress events only move forward

### Rules

- Each rule against a synthetic profile in the fake FS (for example `C:\Users\alice\AppData\Local\npm-cache` with 3 GB of fake files) gives a finding with the right size, tier and actions
- Profile expansion: `Default`, `Public` and `All Users` skipped; several users handled
- Tool missing: action hidden. App running: action blocked with a message
- Unrecognized folders and growth, with two snapshots

### Parsers (golden files in `testdata/`)

- `wsl --list --verbose` in UTF-16 with NUL bytes, exactly what the manual scan ran into
- DISM `/English` output for `AnalyzeComponentStore` and `Get-ReservedStorageState`, and its `\r` progress bar
- `docker system df` JSON lines
- CIM JSON for one item and for several (`ConvertTo-Json` returns an object for one item and an array for several)
- Disk Cleanup handler registry fixtures

### Command runner (L3, with a helper exe)

`TestMain` builds `internal/execx/testhelper` into `.tmp`. The helper prints lines, writes UTF-16, sleeps, starts a grandchild process and exits with a chosen code. Tests cover streaming order, decoding, a timeout that kills the whole tree (Job Object), cancel, exit codes, and argument quoting (spaces, quotes, Unicode).

### API (`httptest`, fake system)

- No token gives 401; a wrong `Host` gives 421; a foreign `Origin` on a POST gives 403
- The launch code works once and expires
- An unknown or expired `planId` gives 409; a second job while busy is queued
- Unknown JSON fields are rejected, so there's no way to slip in a path
- Events arrive in order, heartbeats flow, and `Last-Event-ID` resumes the stream
- Reveal only works for paths the scan found

### UI (Playwright, optional, demo mode)

Quick scan → findings → preview → confirm → live progress → history; cancelling a scan; a failing job; server restart and reconnect; dark mode; a narrow window.

## 4. Read-only smoke tests (L5)

`scripts\test.ps1 -Smoke` (normal rights) and `scripts\test.ps1 -Smoke -Elevated` (only for the DISM analysis). They:

- enumerate the real `C:\` up to a cap (for example the first 200,000 entries) and expect nothing beyond normal access-denied errors;
- compare free space with what PowerShell reports;
- query the Recycle Bin size, restore-point storage, WSL distros, Docker (if running) and, elevated, `DISM /AnalyzeComponentStore`, which only reads.

They receive only `sysinfo.Reader`. The mutator is never constructed, and its real implementation would panic inside a test anyway. Outside GitHub-hosted runners, `testguard` allows elevation only in this explicit `-Elevated` smoke mode.

## 5. Destructive tests (L6): never on a developer's PC

- **Where**: a GitHub Actions `windows-latest` runner (a fresh VM for every run, thrown away afterwards; needs a GitHub repository), or a local VirtualBox VM with a Windows 11 evaluation image and a snapshot to roll back to. Windows 11 Home has neither Windows Sandbox nor Hyper-V.
- **How**: these tests start the real built `coptimizer.exe` on the throwaway machine and drive it only through its HTTP API. The exe isn't a test binary, so the fuses don't apply to it; the disposable machine is the protection.
- **Gate**: the test files carry the build tag `destructive`, and also require `COPTIMIZER_DESTRUCTIVE=1` **and** proof of a disposable machine: `GITHUB_ACTIONS=true` with `RUNNER_ENVIRONMENT=github-hosted`, or a marker file `C:\COPTIMIZER_DISPOSABLE_VM` that exists only inside the VM. If anything is missing, they skip.
- **What**: create real junk (temp files, an npm cache via `npm cache add`, Recycle Bin items), run each action through the API, then check the freed space and that canary files survived. Also hibernation off and on, creating and deleting a restore point, and DISM component cleanup (weekly, since it's slow).

## 6. Manual checks on a real PC

- Phases 1–2 are read-only: run a full scan and compare a few folders with Explorer's Properties.
- Phase 3: safe actions one at a time, always preview first. Start with ones whose size you already know (Recycle Bin, npm cache), and check `data\history.jsonl` afterwards.
- Phase 4: dry runs only, unless you decide to run one for real.

## 7. How to run

```powershell
scripts\test.ps1                    # L1–L4; refuses to run as Administrator
scripts\test.ps1 -Smoke             # L5 only: read-only checks against the real system
scripts\test.ps1 -Smoke -Elevated   # L5 including the checks that need Administrator
```

Playwright UI tests against `--demo` get their own switch in phase 1.

`test.ps1` points `TMP`, `TEMP` and `GOTMPDIR` at `<repo>\.tmp`, so test sandboxes never land in the system temp folder. It checks formatting with `gofmt`, then runs `go vet ./...` and `go test ./...`.

## 8. Coverage goals

- `safety` and the deleter: every line, plus a kept fuzz corpus.
- `scan`, `rules`, `server`, `jobs`: at least 85%.
- The real Windows implementations (`winfs`, `sysinfo`, `execx`): covered by L3 and L5.
- A new rule is done when it has an entry in space-hogs.md, a fake-FS test, tests for its actions, and one manual check.
