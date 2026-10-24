package rules_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ntson9p/coptimizer/internal/fsx/memfs"
	"github.com/ntson9p/coptimizer/internal/rules"
	"github.com/ntson9p/coptimizer/internal/scan"
	"github.com/ntson9p/coptimizer/internal/testguard"
	"github.com/ntson9p/coptimizer/web"
)

func TestMain(m *testing.M) { testguard.Main(m) }

const (
	mb = int64(1) << 20
	gb = int64(1) << 30
)

var t0 = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

func scanFS(t *testing.T, f *memfs.FS) *scan.Result {
	t.Helper()
	res, err := scan.Run(context.Background(), f, scan.Options{Roots: []string{`C:\`}})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func evaluate(t *testing.T, f *memfs.FS) rules.Report {
	t.Helper()
	return rules.Evaluate(scanFS(t, f), rules.DefaultEnv("Asus"), rules.Options{})
}

func finding(rep rules.Report, id string) *rules.Finding {
	for i := range rep.Findings {
		if rep.Findings[i].ID == id {
			return &rep.Findings[i]
		}
	}
	return nil
}

func wantBytes(t *testing.T, rep rules.Report, id string, bytes int64) {
	t.Helper()
	f := finding(rep, id)
	switch {
	case f == nil && bytes > 0:
		t.Errorf("%s: no finding; want %d bytes", id, bytes)
	case f != nil && f.Bytes != bytes:
		t.Errorf("%s: %d bytes in %v; want %d", id, f.Bytes, paths(f), bytes)
	}
}

func paths(f *rules.Finding) []string {
	var out []string
	for _, it := range f.Items {
		out = append(out, it.Path)
	}
	return out
}

const local = `C:\Users\Asus\AppData\Local`

// TestTheManualScanIsFound checks the acceptance criterion of phase 2: what
// the manual scan in docs/space-hogs.md (section 5) found is found again.
func TestTheManualScanIsFound(t *testing.T) {
	f := memfs.New()
	f.AddFile(`C:\hiberfil.sys`, 4*gb, t0)
	f.AddFile(`C:\pagefile.sys`, 5*gb, t0)
	f.AddFile(`C:\$GetCurrent\media\install.esd`, 3*gb, t0)
	f.AddFile(local+`\npm-cache\_cacache\content-v2\blob`, 9*gb, t0)
	f.AddFile(local+`\wsl\{4c8a0e4f}\ext4.vhdx`, 6*gb, t0)
	f.AddFile(local+`\Google\Chrome\User Data\Default\Cache\Cache_Data\data_1`, 2*gb, t0)
	f.AddFile(local+`\Google\Chrome\User Data\Default\History`, 600*mb, t0)
	f.AddFile(local+`\ms-playwright\chromium-1243\chrome.exe`, 2*gb, t0)
	f.AddFile(local+`\pnpm-cache\metadata\index.json`, 1400*mb, t0)

	rep := evaluate(t, f)
	wantBytes(t, rep, "system.hiberfil", 4*gb)
	wantBytes(t, rep, "system.pagefile", 5*gb)
	wantBytes(t, rep, "updates.update-assistant", 3*gb)
	wantBytes(t, rep, "dev.npm-cache", 9*gb)
	wantBytes(t, rep, "virtual.wsl", 6*gb)
	wantBytes(t, rep, "browsers.chrome-cache", 2*gb)
	wantBytes(t, rep, "dev.browser-testing", 2*gb)
	wantBytes(t, rep, "dev.pnpm", 1400*mb)
	wantBytes(t, rep, "browsers.profile-data", 0) // 600 MB is below its 1 GB minimum
	if rep.Totals[rules.Safe] != (3+9+2+2)*gb+1400*mb || rep.Totals[rules.Moderate] != (4+5+6)*gb {
		t.Errorf("totals = %v", rep.Totals)
	}
}

func TestPerUserRulesCoverEveryProfile(t *testing.T) {
	f := memfs.New()
	f.AddFile(`C:\Users\Asus\AppData\Local\npm-cache\a`, gb, t0)
	f.AddFile(`C:\Users\Bob\AppData\Local\npm-cache\a`, gb, t0)
	f.AddFile(`C:\Users\Default\AppData\Local\npm-cache\a`, gb, t0) // the template for new accounts, not a user
	f.AddJunction(`C:\Users\All Users`)

	rep := evaluate(t, f)
	npm := finding(rep, "dev.npm-cache")
	if npm == nil || npm.Bytes != 2*gb || len(npm.Items) != 2 {
		t.Fatalf("npm cache = %+v; want the two real profiles", npm)
	}
}

// TestSpecificRulesWin checks that a location counts for the most specific
// rule only, and that the findings add up without counting anything twice.
func TestSpecificRulesWin(t *testing.T) {
	f := memfs.New()
	f.AddFile(local+`\Temp\SymbolCache\a.pdb`, gb, t0)
	f.AddFile(local+`\Temp\x.tmp`, 500*mb, t0)
	f.AddFile(`C:\Program Files\Java\jdk\lib.dll`, 2*gb, t0)
	f.AddFile(`C:\Program Files\BigApp\app.dll`, gb, t0)
	f.AddFile(local+`\Google\Chrome\User Data\Default\Cache\data`, gb, t0)
	f.AddFile(local+`\Google\Chrome\User Data\Default\IndexedDB\db`, 2*gb, t0)
	f.AddFile(`C:\Windows\WinSxS\amd64\x.dll`, 2*gb, t0)
	f.AddFile(`C:\Windows\System32\y.dll`, 3*gb, t0)

	res := scanFS(t, f)
	rep := rules.Evaluate(res, rules.DefaultEnv("Asus"), rules.Options{})
	wantBytes(t, rep, "dev.vs-caches", gb)
	wantBytes(t, rep, "personal.temp", 500*mb)
	wantBytes(t, rep, "dev.toolchains", 2*gb)
	wantBytes(t, rep, "system.programs", gb)
	wantBytes(t, rep, "browsers.chrome-cache", gb)
	wantBytes(t, rep, "browsers.profile-data", 2*gb)
	wantBytes(t, rep, "system.component-store", 2*gb)
	wantBytes(t, rep, "system.windows", 3*gb)

	var sum int64
	for _, f := range rep.Findings {
		sum += f.Bytes
	}
	if sum != res.Allocated {
		t.Errorf("findings add up to %d; the scan counted %d", sum, res.Allocated)
	}
}

func TestNodeModulesCountBeforeTheirFolders(t *testing.T) {
	f := memfs.New()
	f.AddFile(`C:\Users\Asus\Documents\app\node_modules\big\x.js`, 600*mb, t0)
	f.AddFile(`C:\Users\Asus\Documents\app\node_modules\.pnpm\node_modules\y.js`, 100*mb, t0)
	f.AddFile(`C:\Users\Asus\Documents\report.docx`, 3*gb, t0)
	for _, name := range []string{"a.js", "b.js", "c.js"} {
		f.AddFile(`C:\Users\Asus\AppData\Roaming\npm\node_modules\tool\`+name, 700*mb, t0)
	}

	rep := evaluate(t, f)
	nm := finding(rep, "dev.node-modules")
	if nm == nil || len(nm.Items) != 1 || nm.Bytes != 700*mb {
		t.Fatalf("node_modules = %+v; want the project's folder once, with its nested node_modules", nm)
	}
	wantBytes(t, rep, "personal.desktop-documents", 3*gb)
	// Global npm packages live in AppData: not a project's node_modules. No rule
	// knows them, so they show up as unrecognized, at the deepest folder.
	if u := finding(rep, "other.unrecognized"); u == nil || u.Items[0].Path != `C:\Users\Asus\AppData\Roaming\npm\node_modules\tool` {
		t.Errorf("global npm packages in AppData = %+v; want them unrecognized, not counted as a project", u)
	}
}

func TestUnrecognizedFolders(t *testing.T) {
	f := memfs.New()
	// Files under 1 GB each, so that no single file counts as a big file.
	for _, name := range []string{"a.pak", "b.pak", "c.pak"} {
		f.AddFile(`C:\GameData\level\`+name, 1000*mb, t0)
		f.AddFile(local+`\VendorX\VideoCache\`+name, 700*mb, t0)
	}
	f.AddFile(local+`\VendorY\small`, 500*mb, t0)
	f.AddFile(local+`\npm-cache\x`, 9*gb, t0)
	f.AddFile(`C:\Users\Asus\backup.vhdx`, 2*gb, t0)

	rep := evaluate(t, f)
	u := finding(rep, "other.unrecognized")
	if u == nil {
		t.Fatal("no unrecognized folders")
	}
	got := map[string]rules.Item{}
	for _, it := range u.Items {
		got[it.Path] = it
	}
	if len(got) != 2 {
		t.Errorf("unrecognized = %v; want GameData\\level and VideoCache only", paths(u))
	}
	if it, ok := got[`C:\GameData\level`]; !ok || it.Bytes != 3000*mb || it.Hint != "" {
		t.Errorf("GameData = %+v; want the deepest folder holding the 3000 MB", it)
	}
	if it, ok := got[local+`\VendorX\VideoCache`]; !ok || it.Hint != "cache" {
		t.Errorf("VideoCache = %+v; want it flagged as looking like a cache", it)
	}
	wantBytes(t, rep, "personal.big-files", 2*gb) // the file in the profile itself
}

func TestBigLogsAndBigFiles(t *testing.T) {
	f := memfs.New()
	f.AddFile(`C:\ProgramData\Vendor\trace.log`, 800*mb, t0)
	f.AddFile(`C:\ProgramData\Vendor\data.bin`, 2*gb, t0)
	f.AddFile(`C:\old-backup.zip`, 5*gb, t0)
	f.AddFile(`C:\Windows\System32\big.dll`, 2*gb, t0)

	rep := evaluate(t, f)
	wantBytes(t, rep, "other.big-logs", 800*mb)
	wantBytes(t, rep, "personal.big-files", 5*gb) // not the ProgramData or Windows files
}

func TestOtherAccounts(t *testing.T) {
	f := memfs.New()
	f.AddFile(`C:\Users\Bob\stuff\video.mp4`, 3*gb, t0)
	f.AddFile(`C:\Users\Bob\AppData\Local\npm-cache\x`, gb, t0)
	f.AddFile(`C:\Users\Asus\stuff\video.mp4`, 3*gb, t0)

	rep := evaluate(t, f)
	acc := finding(rep, "personal.other-accounts")
	if acc == nil || len(acc.Items) != 1 || acc.Items[0].Path != `C:\Users\Bob` || acc.Bytes != 3*gb {
		t.Fatalf("other accounts = %+v; want Bob without his npm cache", acc)
	}
	wantBytes(t, rep, "dev.npm-cache", gb)
}

func TestRestorePointsWithoutAdministratorRights(t *testing.T) {
	f := memfs.New()
	f.Deny(`C:\System Volume Information`)
	rep := evaluate(t, f)
	rp := finding(rep, "system.restore-points")
	if rp == nil || !rp.Items[0].Unreadable || rp.Bytes != 0 {
		t.Fatalf("restore points = %+v; want an unreadable item", rp)
	}

	f = memfs.New()
	f.AddFile(`C:\System Volume Information\{3808876b-c176-4e48-b7ae-04046e6cc752}`, 2*gb, t0)
	wantBytes(t, evaluate(t, f), "system.restore-points", 2*gb)
}

func TestSmallFindingsAreLeftOut(t *testing.T) {
	f := memfs.New()
	f.AddFile(local+`\npm-cache\x`, 100*mb, t0)
	if npm := finding(evaluate(t, f), "dev.npm-cache"); npm != nil {
		t.Errorf("a 100 MB npm cache should not be reported: %+v", npm)
	}
}

func TestGrowth(t *testing.T) {
	f := memfs.New()
	f.AddFile(local+`\npm-cache\_cacache\old`, 2*gb, t0)
	f.AddFile(`C:\Users\Asus\Videos\a.mp4`, gb, t0)
	before := scanFS(t, f)
	snap := rules.TakeSnapshot(before.Roots[0], t0, true)

	f.AddFile(local+`\npm-cache\_cacache\new\blob`, 2*gb, t0)
	f.AddFile(`C:\Users\Asus\Videos\b.mp4`, gb, t0)
	f.AddFile(`C:\Users\Asus\Videos\tiny.txt`, mb, t0)
	rep := rules.Evaluate(scanFS(t, f), rules.DefaultEnv("Asus"), rules.Options{Previous: []rules.Snapshot{snap}})

	g := finding(rep, "other.growth")
	if g == nil || len(g.Items) != 2 {
		t.Fatalf("growth = %+v; want two folders", g)
	}
	byPath := map[string]rules.Item{}
	for _, it := range g.Items {
		byPath[it.Path] = it
	}
	if it := byPath[local+`\npm-cache\_cacache\new`]; it.Bytes != 2*gb || it.Current != 2*gb {
		t.Errorf("npm growth = %+v; want the new folder, 2 GB", it)
	}
	if it := byPath[`C:\Users\Asus\Videos`]; it.Bytes != gb+mb || it.Current != 2*gb+mb {
		t.Errorf("Videos growth = %+v", it)
	}
	if !rep.GrowthSince.Equal(t0) {
		t.Errorf("growth since %v; want %v", rep.GrowthSince, t0)
	}
	var sum int64
	for _, x := range rep.Findings {
		if x.ID != "other.growth" {
			sum += x.Bytes
		}
	}
	if total := rep.Totals[rules.Safe] + rep.Totals[rules.Moderate] + rep.Totals[rules.Manual] + rep.Totals[rules.Info]; total != sum {
		t.Errorf("totals %d include the growth finding; want %d", total, sum)
	}
}

func TestSnapshotKeepsTheBigFolders(t *testing.T) {
	f := memfs.New()
	f.AddFile(`C:\big\a`, 100*mb, t0)
	f.AddFile(`C:\small\b`, 10*mb, t0)
	f.AddJunction(`C:\link`)
	s := rules.TakeSnapshot(scanFS(t, f).Roots[0], t0, false)
	if len(s.Folders) != 2 || s.Folders[`C:\`] != 110*mb || s.Folders[`C:\big`] != 100*mb {
		t.Errorf("snapshot = %v; want C:\\ and C:\\big", s.Folders)
	}
}

func TestReadsEnvironmentLikeWindows(t *testing.T) {
	t.Setenv("SystemDrive", `D:`)
	t.Setenv("SystemRoot", `D:\WINDOWS`)
	t.Setenv("PUBLIC", `D:\Users\Public`)
	t.Setenv("USERPROFILE", `D:\Users\me`)
	e := rules.SystemEnv()
	if e.SystemDrive != `D:` || e.Windows != `D:\WINDOWS` || e.Users != `D:\Users` || e.CurrentProfile != `D:\Users\me` {
		t.Errorf("env = %+v", e)
	}
}

func TestCatalogIsWellFormed(t *testing.T) {
	vars := []string{"{SystemDrive}", "{Windows}", "{ProgramData}", "{ProgramFiles}", "{ProgramFilesX86}", "{Users}",
		"{Profile}", "{LocalAppData}", "{AppData}"}
	seen := map[string]bool{}
	for _, r := range rules.Rules() {
		if seen[r.ID] {
			t.Errorf("%s: duplicate ID", r.ID)
		}
		seen[r.ID] = true
		if !strings.HasPrefix(r.ID, string(r.Category)+".") {
			t.Errorf("%s: ID doesn't start with its category %q", r.ID, r.Category)
		}
		switch r.Risk {
		case rules.Safe, rules.Moderate, rules.Manual, rules.Info:
		default:
			t.Errorf("%s: unknown risk %q", r.ID, r.Risk)
		}
		for _, p := range append(append([]string{}, r.Folders...), r.Files...) {
			ok := false
			for _, v := range vars {
				ok = ok || strings.HasPrefix(p, v+`\`) || p == v
			}
			if !ok || strings.Count(p, "{") != 1 || strings.Contains(p, "/") {
				t.Errorf("%s: pattern %q must start with one known variable and use backslashes", r.ID, p)
			}
		}
		if r.Min <= 0 {
			t.Errorf("%s: no minimum size", r.ID)
		}
	}
}

// TestEveryRuleHasTexts checks web/i18n/rules.en.json against the catalog.
func TestEveryRuleHasTexts(t *testing.T) {
	data, err := web.Files.ReadFile("i18n/rules.en.json")
	if err != nil {
		t.Fatal(err)
	}
	var texts map[string]string
	if err := json.Unmarshal(data, &texts); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, r := range rules.Rules() {
		for _, k := range []string{"title", "what", "how"} {
			want["rule."+r.ID+"."+k] = true
		}
		want["category."+string(r.Category)] = true
		want["risk."+string(r.Risk)] = true
	}
	for k := range want {
		if strings.TrimSpace(texts[k]) == "" {
			t.Errorf("rules.en.json has no text for %s", k)
		}
	}
	for k := range texts {
		if !want[k] {
			t.Errorf("rules.en.json has %s, which no rule uses", k)
		}
	}
}

// The scanner's view of a hard-linked file shouldn't make findings depend on
// which name was met first: run the same evaluation on shuffled listings.
func TestFindingsAreStable(t *testing.T) {
	f := memfs.New()
	f.AddFile(`C:\Windows\WinSxS\amd64\x.dll`, 2*gb, t0)
	f.AddHardLink(`C:\Windows\System32\x.dll`, `C:\Windows\WinSxS\amd64\x.dll`)
	f.AddFile(`C:\Windows\WinSxS\Backup\old.dll`, 2*gb, t0)
	var first []rules.Finding
	for i := range 10 {
		res, err := scan.Run(context.Background(), f, scan.Options{Roots: []string{`C:\`}, Workers: 1 + i})
		if err != nil {
			t.Fatal(err)
		}
		rep := rules.Evaluate(res, rules.DefaultEnv("Asus"), rules.Options{})
		if i == 0 {
			first = rep.Findings
			continue
		}
		a, _ := json.Marshal(first)
		b, _ := json.Marshal(rep.Findings)
		if string(a) != string(b) {
			t.Fatalf("run %d differs:\n%s\n%s", i, a, b)
		}
	}
	wantBytes(t, rules.Report{Findings: first}, "system.component-store", 2*gb) // the shared file counts in System32
}
