# COptimizer

Finds what is filling the Windows system drive (C:) and helps reclaim the space safely. A Go server runs as Administrator on `127.0.0.1`, and you control it from a page in your browser.

**Status: phase 0 of 5.** The project setup and the safety fuses that every test relies on are in place. The app doesn't scan or clean anything yet; the first usable cleanups come in phase 3.

## Documentation

- [docs/plan.md](docs/plan.md): architecture, security and safety model, API, phases
- [docs/space-hogs.md](docs/space-hogs.md): what eats space on C: and how to reclaim each item
- [docs/testing.md](docs/testing.md): how the app is tested without risking anyone's PC

## Development

You need Windows 10 22H2 or Windows 11 and Go at the version in `go.mod`.

```powershell
scripts\test.ps1    # all tests; refuses to run as Administrator
scripts\build.ps1   # builds dist\coptimizer.exe
```

Tests can only change files inside their own throwaway folders under `.tmp\`, and they stop if started from an elevated terminal. See [docs/testing.md](docs/testing.md).

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE).
