package sysinfo

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// TestMutatorsGuardFirst checks, by reading the source, that every method of
// RealMutator calls a safety guard before anything else. Calling them in a
// test to see the fuse trip would change the real machine if the guard were
// missing, so this test never calls them.
func TestMutatorsGuardFirst(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "mutator_windows.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	methods := 0
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv == nil {
			continue
		}
		if id, ok := fn.Recv.List[0].Type.(*ast.Ident); !ok || id.Name != "RealMutator" {
			continue
		}
		methods++
		ok = false
		if len(fn.Body.List) > 0 {
			if es, isExpr := fn.Body.List[0].(*ast.ExprStmt); isExpr {
				if call, isCall := es.X.(*ast.CallExpr); isCall {
					if sel, isSel := call.Fun.(*ast.SelectorExpr); isSel {
						if pkg, isID := sel.X.(*ast.Ident); isID && pkg.Name == "safety" && sel.Sel.Name == "GuardSystemChange" {
							ok = true
						}
					}
				}
			}
		}
		if !ok {
			t.Errorf("RealMutator.%s must start with safety.GuardSystemChange(…)", fn.Name.Name)
		}
	}
	if methods == 0 {
		t.Fatal("no RealMutator methods found")
	}
}
