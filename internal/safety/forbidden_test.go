package safety_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// allowed lists the only files that may use the risky APIs below, and why.
// Each must call the matching safety guard before every change it makes.
// Adding an entry is a security-relevant change: review it as one.
var allowed = map[string][]string{
	// Resolves links, read-only (FILE_READ_ATTRIBUTES).
	"internal/safety/realpath_windows.go": {"golang.org/x/sys/windows"},
	// Asks whether the process token is elevated.
	"internal/testguard/testguard.go": {"golang.org/x/sys/windows"},
	// Lists folders, read-only (FILE_LIST_DIRECTORY); never opens files.
	"internal/winfs/list_windows.go": {"golang.org/x/sys/windows"},
	// The deleter's real file system: opens each folder as an os.Root, which
	// refuses paths through junctions; every deletion is guarded by
	// safety.GuardDelete.
	"internal/winfs/clean_windows.go": {"golang.org/x/sys/windows", "os.OpenRoot"},
	// Enables SeBackupPrivilege (read access) in this process only.
	"internal/winfs/privilege_windows.go": {"golang.org/x/sys/windows"},
	// Reads drive sizes, the process token, the names of running programs
	// and the Recycle Bin's size.
	"internal/sysinfo/sysinfo_windows.go": {"golang.org/x/sys/windows", "unsafe"},
	// Empties the Recycle Bin through the shell; guarded by
	// safety.GuardSystemChange.
	"internal/sysinfo/mutator_windows.go": {"golang.org/x/sys/windows", "unsafe"},
	// Starts the elevated server and opens the browser; guarded by
	// safety.GuardShellOpen.
	"cmd/coptimizer/shell_windows.go": {"golang.org/x/sys/windows"},
	// Creates the app's data folder, then writes scan snapshots through
	// winfs.OpenRoot's handle; guarded by safety.GuardWrite and GuardDelete.
	"internal/store/store.go": {"os.MkdirAll"},
	// Runs programs, guarded by safety.GuardRun, inside a job object.
	"internal/execx/real_windows.go": {"golang.org/x/sys/windows", "os/exec", "syscall", "unsafe"},
	// Reads the registry: keys are opened with query and enumerate rights only.
	"internal/probe/registry_windows.go": {"golang.org/x/sys/windows/registry"},
	// The test binary starts itself as a grandchild, and checks that the job
	// stopped it; it also asks Windows which processes share its console.
	"internal/execx/real_test.go": {"golang.org/x/sys/windows", "os/exec", "unsafe"},
	// Test helpers; every change is checked by safety.GuardWrite or GuardDelete first.
	"internal/sandbox/sandbox.go":          {"os.Link", "os.MkdirAll", "os.WriteFile"},
	"internal/sandbox/junction_windows.go": {"golang.org/x/sys/windows", "os.Mkdir", "os.Remove"},
	"internal/sandbox/attrs_windows.go":    {"golang.org/x/sys/windows"},
}

// Functions of package os that create, change or delete files or start
// programs.
var riskyOS = map[string]bool{
	"Chmod": true, "Chown": true, "Chtimes": true, "CopyFS": true, "Create": true,
	"CreateTemp": true, "Lchown": true, "Link": true, "Mkdir": true, "MkdirAll": true,
	"MkdirTemp": true, "NewFile": true, "OpenFile": true, "OpenInRoot": true,
	"OpenRoot": true, "Remove": true, "RemoveAll": true, "Rename": true,
	"StartProcess": true, "Symlink": true, "Truncate": true, "WriteFile": true,
}

// riskyImport reports whether importing path alone gives raw access to the
// system.
func riskyImport(path string) bool {
	switch path {
	case "os/exec", "syscall", "unsafe", "io/ioutil":
		return true
	}
	return strings.HasPrefix(path, "golang.org/x/sys/")
}

// TestForbiddenAPIs keeps every way of changing the machine in the few
// reviewed files listed in allowed. Any other file, production or test, that
// imports a low-level package or calls a mutating function of package os
// fails this test.
func TestForbiddenAPIs(t *testing.T) {
	root := moduleRoot(t)
	used := make(map[string]bool)
	for _, file := range goFiles(t, root) {
		rel := relPath(t, root, file)
		fset, f := parseFile(t, file)
		for _, u := range riskyUses(f) {
			if isAllowed(rel, u.what) {
				used[rel+" "+u.what] = true
				continue
			}
			t.Errorf("%s:%d: %s is not allowed here; see the allowed list in internal/safety/forbidden_test.go",
				rel, fset.Position(u.pos).Line, u.what)
		}
	}
	for file, whats := range allowed {
		for _, what := range whats {
			if !used[file+" "+what] {
				t.Errorf("%s no longer uses %s; remove it from the allowed list", file, what)
			}
		}
	}
}

// TestEveryTestPackageUsesTestguard makes every package with tests start them
// through testguard.Main, which refuses to run as Administrator.
func TestEveryTestPackageUsesTestguard(t *testing.T) {
	root := moduleRoot(t)
	guarded := make(map[string]bool) // package folder → has a TestMain calling testguard.Main
	for _, file := range goFiles(t, root) {
		if !strings.HasSuffix(file, "_test.go") {
			continue
		}
		dir := relPath(t, root, filepath.Dir(file))
		_, f := parseFile(t, file)
		guarded[dir] = guarded[dir] || callsTestguardMain(f)
	}
	for dir, ok := range guarded {
		if !ok {
			t.Errorf("%s: tests must start with func TestMain(m *testing.M) { testguard.Main(m) }", dir)
		}
	}
}

type use struct {
	what string
	pos  token.Pos
}

func riskyUses(f *ast.File) []use {
	var uses []use
	osName := ""
	for _, imp := range f.Imports {
		path, _ := strconv.Unquote(imp.Path.Value)
		if riskyImport(path) {
			uses = append(uses, use{path, imp.Pos()})
		}
		if path == "os" {
			osName = "os"
			if imp.Name != nil {
				osName = imp.Name.Name
			}
			if osName == "." {
				uses = append(uses, use{"dot-import of os", imp.Pos()})
			}
		}
	}
	if osName == "" || osName == "." || osName == "_" {
		return uses
	}
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == osName && riskyOS[sel.Sel.Name] {
			uses = append(uses, use{"os." + sel.Sel.Name, sel.Pos()})
		}
		return true
	})
	return uses
}

func callsTestguardMain(f *ast.File) bool {
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Name.Name != "TestMain" || fn.Body == nil {
			continue
		}
		found := false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Main" {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "testguard" {
						found = true
					}
				}
			}
			return !found
		})
		if found {
			return true
		}
	}
	return false
}

func isAllowed(file, what string) bool {
	for _, w := range allowed[file] {
		if w == what {
			return true
		}
	}
	return false
}

// moduleRoot finds the folder holding go.mod, starting from the package
// folder that go test runs in.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// goFiles lists every Go file of the module, skipping folders that the go
// tool ignores or that hold no source.
func goFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if p != root && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") ||
				name == "testdata" || name == "node_modules" || name == "dist" || name == "data") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, ".go") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func parseFile(t *testing.T, file string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	return fset, f
}

func relPath(t *testing.T, root, p string) string {
	t.Helper()
	rel, err := filepath.Rel(root, p)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.ToSlash(rel)
}
