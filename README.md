# COptimizer

Finds what is filling the Windows system drive (C:) and helps reclaim the space safely. A Go server runs as Administrator on `127.0.0.1`, and you control it from a page in your browser.

**Status: phase 3 of 5.** COptimizer scans a drive, shows where the space goes, and recognizes 84 kinds of space hogs (caches, leftovers, virtual disks, AI models, personal files…), explaining for each how to reclaim the space. It flags big folders it doesn't recognize and what grew since the last scan.

It can clean the safe ones itself: temp folders, package-manager, browser, editor and chat-app caches, crash dumps, driver and update leftovers, the Recycle Bin, Delivery Optimization files, and Windows' component store through DISM. Every cleanup starts with a preview of exactly what it will delete; nothing happens until you confirm. It deletes only in your own profile and in the Windows folders a cleanup names, never follows junctions or links, leaves files in use alone, and asks you to close a program first when its cache is in use. Personal files (Documents, Downloads, photos…) are only ever reported. Simulation mode (on the Activity page, or `-simulate`) makes every cleanup show what it would do without deleting anything.

Try it: there are no releases yet, so build it with `scripts\build.ps1`, then run `dist\coptimizer.exe`:

- `coptimizer.exe`: asks once for Administrator rights (so every folder can be measured) and opens the page in your browser.
- `coptimizer.exe -demo`: a simulated PC; needs no Administrator rights and reads nothing on your computer. Its cleanups only delete simulated files.

COptimizer keeps its own data in a `data` folder next to the exe: earlier scans (to show what grew) and `history.jsonl`, a record of every cleanup.

## Documentation

- [docs/plan.md](docs/plan.md): architecture, security and safety model, API, phases
- [docs/space-hogs.md](docs/space-hogs.md): what eats space on C: and how to reclaim each item
- [docs/testing.md](docs/testing.md): how the app is tested without risking anyone's PC

## Development

You need Windows 10 22H2 or Windows 11 and Go at the version in `go.mod`.

```powershell
scripts\test.ps1       # all tests; refuses to run as Administrator
scripts\test.ps1 -UI   # plus the browser tests (needs Node.js and Chrome)
scripts\build.ps1      # builds dist\coptimizer.exe
scripts\dev.ps1        # runs demo mode from source
```

Tests can only change files inside their own throwaway folders under `.tmp\`, and they stop if started from an elevated terminal. Real cleanups with Administrator rights are tested only on GitHub's throwaway CI machines (`scripts\destructive.ps1`, which refuses to run anywhere else). See [docs/testing.md](docs/testing.md).

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE).
