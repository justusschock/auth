package apitoken

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzParseToken(f *testing.F) {
	f.Add("dtc_" + strings.Repeat("a", idChars) + "_" + strings.Repeat("a", secretChars))
	f.Add("dtc_" + strings.Repeat("7", idChars) + "_" + strings.Repeat("7", secretChars))
	f.Add("dtc__")
	f.Add("")
	f.Fuzz(func(t *testing.T, value string) {
		id, ok := parseToken(value, "dtc")
		if !ok {
			if id != "" {
				t.Fatal("rejected token returned an ID")
			}
			return
		}
		if !ValidID(id) || len(value) > maxTokenSize {
			t.Fatalf("accepted token with invalid ID %q", id)
		}
		secret, err := encoding.DecodeString(value[len(value)-secretChars:])
		if err != nil || len(secret) != secretBytes {
			t.Fatal("accepted token with invalid secret")
		}
		if formatToken("dtc", id, secret) != value {
			t.Fatal("accepted non-canonical token")
		}
	})
}

func TestDigestsEqualIsExact(t *testing.T) {
	a := digest(nil, "dtc_a")
	for index := range a {
		b := a
		b[index] ^= 0x01
		if digestsEqual(a, b) {
			t.Fatalf("digests differing at byte %d compared equal", index)
		}
	}
	if !digestsEqual(a, a) || !zeroDigest([32]byte{}) || zeroDigest(a) {
		t.Fatal("digest comparison is wrong")
	}
	if digest(nil, "x") == digest([]byte("k"), "x") {
		t.Fatal("pepper does not change digest")
	}
}

// TestDigestComparisonsAreConstantTime asserts that production code compares
// token digests only through crypto/subtle and never with variable-time
// operators or helpers.
func TestDigestComparisonsAreConstantTime(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	usesSubtle := false
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, name, source, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.SelectorExpr:
				if pkg, ok := n.X.(*ast.Ident); ok {
					switch {
					case pkg.Name == "bytes" && (n.Sel.Name == "Equal" || n.Sel.Name == "Compare"):
						t.Errorf("%s uses bytes.%s", fset.Position(n.Pos()), n.Sel.Name)
					case pkg.Name == "subtle" && n.Sel.Name == "ConstantTimeCompare":
						usesSubtle = true
					}
				}
			case *ast.BinaryExpr:
				if n.Op == token.EQL || n.Op == token.NEQ {
					if digestOperand(n.X) || digestOperand(n.Y) {
						t.Errorf("%s compares a digest with %s", fset.Position(n.Pos()), n.Op)
					}
				}
			}
			return true
		})
	}
	if !usesSubtle {
		t.Fatal("digest comparison does not use crypto/subtle")
	}
}

func digestOperand(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.SelectorExpr:
		return e.Sel.Name == "Digest"
	case *ast.Ident:
		return e.Name == "presented" || strings.Contains(strings.ToLower(e.Name), "digest")
	case *ast.CallExpr:
		if ident, ok := e.Fun.(*ast.Ident); ok {
			return ident.Name == "digest"
		}
	}
	return false
}
