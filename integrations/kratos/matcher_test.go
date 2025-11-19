package kratos

import "testing"

func TestExactMatcher(t *testing.T) {
	matcher := &ExactMatcher{operation: "/api/user/info"}

	tests := []struct {
		name      string
		operation string
		want      bool
	}{
		{"exact match", "/api/user/info", true},
		{"no match", "/api/user/list", false},
		{"partial match", "/api/user", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matcher.Match(tt.operation); got != tt.want {
				t.Errorf("ExactMatcher.Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPrefixMatcher(t *testing.T) {
	matcher := &PrefixMatcher{prefix: "/api/admin"}

	tests := []struct {
		name      string
		operation string
		want      bool
	}{
		{"exact match", "/api/admin", true},
		{"prefix match", "/api/admin/user", true},
		{"no match", "/api/user", false},
		{"partial match", "/api/adm", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matcher.Match(tt.operation); got != tt.want {
				t.Errorf("PrefixMatcher.Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSuffixMatcher(t *testing.T) {
	matcher := &SuffixMatcher{suffix: "/delete"}

	tests := []struct {
		name      string
		operation string
		want      bool
	}{
		{"exact match", "/delete", true},
		{"suffix match", "/api/user/delete", true},
		{"no match", "/api/user/list", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matcher.Match(tt.operation); got != tt.want {
				t.Errorf("SuffixMatcher.Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWildcardMatcher(t *testing.T) {
	tests := []struct {
		name      string
		pattern   string
		operation string
		want      bool
	}{
		{"star wildcard", "/api/*/info", "/api/user/info", true},
		{"star wildcard no match", "/api/*/info", "/api/user/list", false},
		{"question mark", "/api/user/?", "/api/user/1", true},
		{"question mark no match", "/api/user/?", "/api/user/10", false},
		{"multiple stars", "/api/*/user/*", "/api/v1/user/info", true},
		{"star at end", "/api/admin/*", "/api/admin/user/delete", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := &WildcardMatcher{pattern: tt.pattern}
			if got := matcher.Match(tt.operation); got != tt.want {
				t.Errorf("WildcardMatcher.Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRegexMatcher(t *testing.T) {
	tests := []struct {
		name      string
		pattern   string
		operation string
		want      bool
	}{
		{"digit pattern", "^/api/user/\\d+$", "/api/user/123", true},
		{"digit pattern no match", "^/api/user/\\d+$", "/api/user/abc", false},
		{"word pattern", "^/api/\\w+/info$", "/api/user/info", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := newRegexMatcher(tt.pattern)
			if got := matcher.Match(tt.operation); got != tt.want {
				t.Errorf("RegexMatcher.Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestContainsMatcher(t *testing.T) {
	matcher := &ContainsMatcher{substring: "/admin/"}

	tests := []struct {
		name      string
		operation string
		want      bool
	}{
		{"contains match", "/api/admin/user", true},
		{"no match", "/api/user/info", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matcher.Match(tt.operation); got != tt.want {
				t.Errorf("ContainsMatcher.Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFuncMatcher(t *testing.T) {
	matcher := &FuncMatcher{
		fn: func(operation string) bool {
			return len(operation) > 10
		},
	}

	tests := []struct {
		name      string
		operation string
		want      bool
	}{
		{"length > 10", "/api/user/info", true},
		{"length <= 10", "/api/user", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matcher.Match(tt.operation); got != tt.want {
				t.Errorf("FuncMatcher.Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAndMatcher(t *testing.T) {
	matcher := &AndMatcher{
		matchers: []OperationMatcher{
			&PrefixMatcher{prefix: "/api/"},
			&SuffixMatcher{suffix: "/info"},
		},
	}

	tests := []struct {
		name      string
		operation string
		want      bool
	}{
		{"both match", "/api/user/info", true},
		{"first match only", "/api/user/list", false},
		{"second match only", "/user/info", false},
		{"none match", "/user/list", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matcher.Match(tt.operation); got != tt.want {
				t.Errorf("AndMatcher.Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOrMatcher(t *testing.T) {
	matcher := &OrMatcher{
		matchers: []OperationMatcher{
			&PrefixMatcher{prefix: "/api/admin"},
			&SuffixMatcher{suffix: "/delete"},
		},
	}

	tests := []struct {
		name      string
		operation string
		want      bool
	}{
		{"first match", "/api/admin/user", true},
		{"second match", "/api/user/delete", true},
		{"both match", "/api/admin/delete", true},
		{"none match", "/api/user/info", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matcher.Match(tt.operation); got != tt.want {
				t.Errorf("OrMatcher.Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNotMatcher(t *testing.T) {
	matcher := &NotMatcher{
		matcher: &PrefixMatcher{prefix: "/api/public"},
	}

	tests := []struct {
		name      string
		operation string
		want      bool
	}{
		{"not match", "/api/admin/user", true},
		{"match", "/api/public/info", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matcher.Match(tt.operation); got != tt.want {
				t.Errorf("NotMatcher.Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewPatternMatcher(t *testing.T) {
	tests := []struct {
		name        string
		pattern     string
		operation   string
		want        bool
		matcherType string
	}{
		{"exact pattern", "/api/user/info", "/api/user/info", true, "exact"},
		{"wildcard pattern", "/api/*/info", "/api/user/info", true, "wildcard"},
		{"question pattern", "/api/user/?", "/api/user/1", true, "wildcard"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := newPatternMatcher(tt.pattern)
			if got := matcher.Match(tt.operation); got != tt.want {
				t.Errorf("newPatternMatcher().Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCombinedMatchers(t *testing.T) {
	// Test And() helper function
	andMatcher := And(
		&PrefixMatcher{prefix: "/api/"},
		&ContainsMatcher{substring: "admin"},
	)

	if !andMatcher.Match("/api/admin/user") {
		t.Error("And() matcher should match")
	}
	if andMatcher.Match("/api/user/info") {
		t.Error("And() matcher should not match")
	}

	// Test Or() helper function
	orMatcher := Or(
		&PrefixMatcher{prefix: "/public/"},
		&SuffixMatcher{suffix: "/login"},
	)

	if !orMatcher.Match("/public/info") {
		t.Error("Or() matcher should match")
	}
	if !orMatcher.Match("/api/user/login") {
		t.Error("Or() matcher should match")
	}
	if orMatcher.Match("/api/user/info") {
		t.Error("Or() matcher should not match")
	}

	// Test Not() helper function
	notMatcher := Not(&PrefixMatcher{prefix: "/api/"})

	if notMatcher.Match("/api/user/info") {
		t.Error("Not() matcher should not match")
	}
	if !notMatcher.Match("/public/info") {
		t.Error("Not() matcher should match")
	}
}
