# COptimizer: testing strategy

## Principle

Run real tests, but build them so they **cannot** touch anything outside throwaway folders. Reviewing the code in your head is not enough.

The riskiest code in this app deletes files and runs system tools as Administrator. If it were only reviewed, its first real run would happen as Administrator on someone's PC: the worst place to find a bug such as a path check that treats `C:\Temp2` as inside `C:\Temp`, or a junction that leads into Documents. Running that code thousands of times against fake and sandboxed folders is far safer than never running it before release. The real danger is a *test* touching real data, and that can be ruled out by construction.

## 1. Six independent protections

1. **Design**: every side effect goes through an interface: the filesystem (`fsx.Lister`, and `fsx.Cleaner` for deleting), the command runner (`execx`), the system (`sysinfo.Reader` and `sysinfo.Mutator`). Core logic, the deleter included, is tested with in-memory fakes; the real implementations are kept thin.
2. **Forbidden-API test**: `internal/safety/forbidden_test.go` parses every Go file in the repository, production and test code alike. Only a short, reviewed list of files may import `os/exec`, `syscall`, `unsafe` or `golang.org/x/sys/...`, or call the `os` functions that create, change or delete files or start programs. A second check makes every package with tests start them through `testguard`.
3. **Sandboxes**: a test that needs a real filesystem gets one from `sandbox.New(t)`: a fresh folder (under `<repo>\.tmp\` when run through `scripts\test.ps1`) that's deleted afterwards. The `sandbox` helpers are the only test code allowed to create files.
4. **Fuses in the production code**: inside a test binary (`testing.Testing()` is true):
   - `GuardWrite` and `GuardDelete` panic unless the path is inside a registered sandbox, both as written and after Windows itself (`GetFinalPathNameByHandle`) has followed every junction and link on the way;
   - `GuardRun` panics for any program except registered test helpers;
   - `GuardShellOpen` (opening a link in the browser, an Explorer window, or the UAC prompt) and `GuardSystemChange` (registry, power options, restore points, Recycle Bin…) panic unconditionally.

   A forgotten fake therefore crashes the test instead of changing the PC. The guards sit right before the system calls: the real deleter calls `GuardDelete` for every file it removes, so even its own tests can only delete inside their sandboxes. Methods that change the system (`RealMutator`) are never called by a test, not even to see the fuse trip, since a missing guard would then change the PC; a test reads their source instead and checks that each starts with its guard.
5. **No admin**: `scripts\test.ps1` and the shared `testguard` `TestMain` refuse to run elevated, so Windows permissions would still block changes to system folders even if everything above failed. They would not protect the user's own files (Documents, Desktop), which a normal process can write; protections 2–4 cover those. The only exceptions are GitHub-hosted CI runners (disposable VMs) and `-Smoke -Elevated`.
6. **Real actions only on disposable machines**: tests that really clean Windows folders run only on a throwaway VM or CI runner, behind two independent checks (section 5).

The protections are tested themselves. A planted forbidden call, or a test package that skips `testguard`, makes the suite fail. A fuse weakened to skip the link check makes the junction tests fail. Go fuzzing checks the path rules against generated input.

Code that deletes or changes things also gets independent reviews before it first runs on a real PC: reviewers who read the code fresh, with the threat model but not the author's conclusions, look for what the tests don't cover. Phase 3's cleanup code had two. They found no way for the deleter to reach anything outside an approved folder; the other findings were fixed, each with a test (listed below).

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

`internal/clean` against the in-memory file system, and `internal/winfs` against real folders in sandboxes:

- The contents go and the folder stays; with `RemoveRoot` the folder goes too
- A junction inside the folder being cleaned, pointing at a **canary** folder: the junction and the canary are untouched. The canary sits in the same sandbox, so the fuses wouldn't stop a buggy deleter: the test checks the deleter itself
- The folder itself is a junction: refused. Opened by its 8.3 short name: refused
- **A folder swapped for a junction after the folder was opened**, as malware racing the deleter might: listing and deleting through it are refused, and removing the junction leaves its target alone
- Read-only, hidden and system files: deleted. A hard link: only that name goes
- A file held open without delete sharing: skipped, reported "in use", the cleanup ends as `partial`
- A file the user may not delete (the test sets a deny entry on its own sandbox, restored afterwards): skipped, reported "denied"
- `MinAge` boundaries, counted from the later of creation and last change, and fresh empty folders kept; `Include` and `Exclude`
- The deny list decides for every folder and file, and a folder that resolves elsewhere is refused even if the file system says it opened it
- Online-only files: never touched. Cancel half-way: what was reported deleted is exactly what is gone
- **Dry-run parity** (a property test on 30 random trees): the dry run reports exactly what the real run then deletes
- Long paths (over 260 characters), also for the folder being cleaned itself, and Vietnamese names; a 100,000-file folder in about a second
- Unusual turns: a file gone before its turn counts as gone, not as a problem; a single file that is really a folder, or whose folder can't be listed, is refused with the reason; a folder that can't be removed, or whose parent can't be opened or resolves elsewhere, stays

**Mutation checks**: each protection (links skipped, the deny list per entry, the resolved-path checks, age from creation, the exception rule, fresh folders kept) was weakened on purpose, one at a time; a test failed every time.

### Deny list

Table tests for every protected tree, exception and general folder; spelling variants (case, `/`, `\\?\`); a known folder moved inside an exception stays protected; a missing system folder makes the policy refuse to build. Go fuzzing checks that spellings Windows treats as the same path always get the same answer, and that nothing in System32 or a profile root is ever allowed.

### Actions

- **Reviewed list**: a test lists every location a deletion may clean, with its options (`only *.log *.cab`, `older than 24h`, `folder too`). Any change to the catalog's deletable locations makes it fail until the list is updated, so the change is reviewed, like the forbidden-API list.
- Every deletable location, expanded on a standard PC, passes the deny list; actions name only their rule's folders; only Safe findings can be deleted.
- Plans on simulated PCs: only your own profile (another account's cache is listed as left alone), system folders only with Administrator rights, locations that need their own tool left out (pnpm's store), other findings' folders inside a folder left to them (`Temp\SymbolCache`), recent temp files kept, programs that must be closed, the Recycle Bin, DISM's exact command, its progress bar and exit codes (3010: restart needed), Delivery Optimization's command. A simulation changes nothing.
- A Recycle Bin that changed since its preview is not emptied; one already empty is left alone. DISM's cleanup waits while a DISM analysis runs, and can be stopped while it waits. A single file (a memory dump) is measured again on its own, not with all of `C:\Windows`. Every failure ends a preview or a cleanup with its reason.

### Cleanup queue and API (`httptest`, fakes)

From preview to history: the preview deletes nothing; the cleanup deletes exactly that; free space grows by it, and "not accounted for" doesn't; events arrive in order; the folders are measured again and the finding goes; the history records it. A preview works once and expires after 10 minutes; a preview made in simulation mode is refused once simulation is off; requests can't name folders; a cleanup waits until Chrome is closed; simulation mode deletes nothing; a running deletion can be stopped, a queued one taken out; DISM's cleanup can't be stopped, and quitting is refused while it runs; once quitting has begun, no cleanup starts. A page that lost its connection gets, after reconnecting, the events it missed.

Quitting from the console: while a cleanup runs, the first Q or Ctrl+C only warns, and a second within 30 seconds quits.

### Measuring again after a cleanup

On copies of a scan: the cleaned folders and every total above them change, the original doesn't; a folder that is gone is removed; one swapped for a junction after the cleanup is kept as a link and nothing behind it is measured; a deleted single file leaves its folder's total; a refresh stops at once when COptimizer is shutting down.

### COptimizer's own data folder (sandboxes)

A data folder that is a junction is refused, and nothing appears behind it; a history file cut off mid-line still takes, and shows, the next entry.

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

### Command runner (L3, the test binary as its own helper)

Started with `COPTIMIZER_EXECX_HELPER` set, the `execx` test binary acts as the program under test instead of running tests: it echoes its arguments, exits with a chosen code, sleeps, floods its output, or starts a grandchild (itself again) and sleeps. It is registered as the only program the fuses let run, so no other program can ever start. Tests cover output and exit codes, argument quoting (spaces, quotes, backslashes, Unicode, `&|<>^`), output line by line (a progress bar redrawn with carriage returns), a timeout and a cancel that stop the whole process tree (the grandchild is checked to be gone), the output cap, that an unregistered program trips the fuse before it can start, and that a program doesn't share the test's console: it lists the processes attached to its console, and the test's own must not be among them. Removing the fix makes that test fail.

### Probes (fakes and fixtures)

Probes read the registry through an interface: tests use an in-memory registry. DISM is never run in tests; its answers come from samples in `internal/probe/testdata` (with Windows line endings and the progress bar), including exit code 740 and output that can't be understood. Without Administrator rights DISM isn't even attempted.

### Findings

Every rule is checked against small simulated drives: the items of the manual scan in space-hogs.md (section 5) are found with the right sizes; per-user rules cover every profile but not `Default`; a location counts for the most specific rule only, and all findings add up to exactly what the scan counted; detectors (`node_modules`, unexplained folders, big files, huge logs, other accounts, growth) find what they should and nothing else. A test checks that every rule has its texts in `rules.en.json`. The scanner gives the same result whatever order the workers meet hard-linked names in (30 shuffled runs).

### API (`httptest`, fake system)

- No token gives 401; a wrong `Host` gives 421; a foreign `Origin` on a POST gives 403
- The launch code works once and expires
- An unknown or expired `planId` gives 409; a second job while busy is queued
- Unknown JSON fields are rejected, so there's no way to slip in a path
- Events arrive in order, heartbeats flow, and `Last-Event-ID` resumes the stream
- Reveal only works for paths the scan found

### UI (Playwright, optional, demo mode)

Scan → explorer → findings → system information; then, on the same simulated PC: preview and clean the npm cache (its finding disappears once the folder is measured again), a cleanup blocked until VS Code is closed, simulation mode, the Recycle Bin, DISM's cleanup with live progress and no Stop button, and the Activity page with the history. A used link doesn't sign in. Screenshots of each step, in light and dark mode. Planned: cancelling a scan, server restart and reconnect, a narrow window.

## 4. Read-only smoke tests (L5)

`scripts\test.ps1 -Smoke` (normal rights) and `scripts\test.ps1 -Smoke -Elevated` (only for the DISM analysis). They:

- enumerate the real `C:\` up to a cap (for example the first 200,000 entries) and expect nothing beyond normal access-denied errors;
- compare free space with what PowerShell reports;
- list the running programs and query the Recycle Bin's size; later restore-point storage, WSL distros, Docker (if running) and, elevated, `DISM /AnalyzeComponentStore`, which only reads.

They receive only `sysinfo.Reader`. The mutator is never constructed, and its real implementation would panic inside a test anyway. Outside GitHub-hosted runners, `testguard` allows elevation only in this explicit `-Elevated` smoke mode.

## 5. Destructive tests (L6): never on a developer's PC

- **Where**: a GitHub Actions `windows-latest` runner (a fresh VM for every run, thrown away afterwards), or a local VirtualBox VM with a Windows 11 evaluation image and a snapshot to roll back to. Windows 11 Home has neither Windows Sandbox nor Hyper-V.
- **How**: `scripts\destructive.ps1` starts the real built `coptimizer.exe -serve` with Administrator rights and drives it only through its HTTP API, as the page does. The exe isn't a test binary, so the fuses don't apply to it; the disposable machine is the protection.
- **Gate**: it does nothing unless `COPTIMIZER_DESTRUCTIVE=1`, and then refuses to run unless the machine proves it is disposable (`GITHUB_ACTIONS=true` with `RUNNER_ENVIRONMENT=github-hosted`, or the marker file `C:\COPTIMIZER_DISPOSABLE_VM` that exists only inside the VM) and it has Administrator rights. CI runs it as its own job on every push.
- **What it checks today**: it puts junk in the user's npm cache (300 MB), temp folder (400 MB, three days old, plus a fresh file) and Recycle Bin (150 MB), a junction in the npm cache that leads to a canary folder, and an old temp file that Windows forbids everyone to delete. Then it scans C:, previews and runs the three cleanups, and checks that the junk is gone; that the fresh temp file, the canary and the junction survive; that the protected file survives and is reported as denied, although COptimizer runs with Administrator rights and its backup privilege on; that free space grew by at least 80% of the estimate; and that `history.jsonl` has three entries.
- **Later** (phase 4): hibernation off and on, creating and deleting a restore point, and DISM component cleanup (weekly, since it's slow).

## 6. Manual checks on a real PC

- Phases 1–2 are read-only: run a full scan and compare a few folders with Explorer's Properties.
- Phase 3: previews were checked read-only on the author's PC (unelevated, in simulation mode, no cleanup started). Real cleanups come next, one at a time and always preview first: start with ones whose size you already know (npm cache, Playwright browsers), and check `data\history.jsonl` afterwards.
- Phase 4: dry runs only, unless you decide to run one for real.

## 7. How to run

```powershell
scripts\test.ps1                    # L1–L4 (API); refuses to run as Administrator
scripts\test.ps1 -UI                # also the browser tests in e2e\ against coptimizer -demo
scripts\test.ps1 -Cover             # also checks each package's coverage minimum (section 8)
scripts\test.ps1 -Race              # with Go's race detector; needs a C compiler (CI has one)
scripts\test.ps1 -Smoke             # L5 only: read-only checks against the real system
scripts\test.ps1 -Smoke -Elevated   # L5 including the checks that need Administrator
scripts\destructive.ps1             # L6: skips unless COPTIMIZER_DESTRUCTIVE=1, refuses unless disposable
```

The browser tests use Node.js, `playwright-core` (no browser download) and the installed Chrome (`COPTIMIZER_E2E_CHANNEL` picks another). They save screenshots in `.tmp\e2e`.

`test.ps1` points `TMP`, `TEMP` and `GOTMPDIR` at `<repo>\.tmp`, so test sandboxes never land in the system temp folder. It checks formatting with `gofmt`, then runs `go vet ./...` and `go test ./...`.

## 8. Coverage goals

`scripts\test.ps1 -Cover` measures which statements the tests run, counting the tests of every package (the deleter is exercised by its own tests and by the real-folder tests in `winfs`), and fails if a package falls below its minimum. CI runs it on every push, and runs the tests a second time with Go's race detector.

| Package | Measured (Oct 2026) | Minimum |
|---|---|---|
| `clean` (the deleter) | 99.4% | 99% |
| `actions` | 100% | 98% |
| `safety` | 95.9% | 95% |
| `rules` | 97.1% | 95% |
| `scan` | 94.6% | 92% |
| `winfs` | 85.9% | 85% |
| `server` | 87.9% | 85% |
| `store` | 88.8% | 85% |

What the tests can't reach: the deleter's guard against removing a drive root, which the deny list already refuses; the fuses' code for the real app; and system calls that can't be made to fail safely (Windows failing to say where a folder it just opened is). The real Windows implementations (`winfs`, `sysinfo`, `execx`) are also covered by L3 and L5.

A new rule is done when it has an entry in space-hogs.md, a fake-FS test, tests for its actions, and one manual check.
