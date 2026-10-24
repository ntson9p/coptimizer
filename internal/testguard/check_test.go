package testguard

import "testing"

func TestCheck(t *testing.T) {
	env := func(kv ...string) func(string) string {
		m := make(map[string]string)
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return func(k string) string { return m[k] }
	}
	cases := []struct {
		name     string
		elevated bool
		getenv   func(string) string
		ok       bool
	}{
		{"normal user", false, env(), true},
		{"administrator", true, env(), false},
		{"GitHub-hosted runner", true, env("GITHUB_ACTIONS", "true", "RUNNER_ENVIRONMENT", "github-hosted"), true},
		{"self-hosted runner", true, env("GITHUB_ACTIONS", "true", "RUNNER_ENVIRONMENT", "self-hosted"), false},
		{"runner variable alone", true, env("RUNNER_ENVIRONMENT", "github-hosted"), false},
		{"elevated smoke tests", true, env("COPTIMIZER_SMOKE_ELEVATED", "1"), true},
		{"smoke flag misspelled", true, env("COPTIMIZER_SMOKE_ELEVATED", "yes"), false},
	}
	for _, c := range cases {
		if err := check(c.elevated, c.getenv); (err == nil) != c.ok {
			t.Errorf("%s: check() = %v; want ok=%v", c.name, err, c.ok)
		}
	}
}
