# COptimizer

Finds what is filling the Windows system drive (C:) and helps reclaim the space safely. A Go server runs as Administrator on `127.0.0.1`, and you control it from a page in your browser.

**Status: phase 1 of 5.** COptimizer can scan a drive and show where the space goes: biggest folders, largest files, file types. It only reads; cleanups arrive in phase 3.

Try it: there are no releases yet, so build it with `scripts\build.ps1`, then run `dist\coptimizer.exe`:

- `coptimizer.exe`: asks once for Administrator rights (so every folder can be measured) and opens the page in your browser.
- `coptimizer.exe -demo`: a simulated PC; needs no Administrator rights and reads nothing on your computer.

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

Tests can only change files inside their own throwaway folders under `.tmp\`, and they stop if started from an elevated terminal. See [docs/testing.md](docs/testing.md).

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE).
