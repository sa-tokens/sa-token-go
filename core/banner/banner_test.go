package banner

import (
	"bytes"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/click33/sa-token-go/core/config"
	"github.com/click33/sa-token-go/core/version"
)

// captureOutput captures stdout output for testing
func captureOutput(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	f()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

func TestPrint(t *testing.T) {
	output := captureOutput(func() {
		Print()
	})

	// Check if output contains expected elements
	if !strings.Contains(output, "Sa-Token-Go") {
		t.Error("Output should contain 'Sa-Token-Go'")
	}

	if !strings.Contains(output, version.Version) {
		t.Errorf("Output should contain version %s", version.Version)
	}

	if !strings.Contains(output, "Go Version") {
		t.Error("Output should contain 'Go Version'")
	}

	if !strings.Contains(output, runtime.Version()) {
		t.Errorf("Output should contain Go version %s", runtime.Version())
	}

	if !strings.Contains(output, "GOOS/GOARCH") {
		t.Error("Output should contain 'GOOS/GOARCH'")
	}

	expectedOS := runtime.GOOS + "/" + runtime.GOARCH
	if !strings.Contains(output, expectedOS) {
		t.Errorf("Output should contain OS/ARCH %s", expectedOS)
	}
}

func TestFormatTimeout(t *testing.T) {
	tests := []struct {
		name     string
		seconds  int64
		expected string
	}{
		{
			name:     "Positive seconds less than a day",
			seconds:  3600,
			expected: "3600 seconds",
		},
		{
			name:     "Exactly one day",
			seconds:  86400,
			expected: "86400 seconds (1 days)",
		},
		{
			name:     "Multiple days",
			seconds:  259200, // 3 days
			expected: "259200 seconds (3 days)",
		},
		{
			name:     "30 days",
			seconds:  2592000,
			expected: "2592000 seconds (30 days)",
		},
		{
			name:     "Zero means never expire",
			seconds:  0,
			expected: neverExpire,
		},
		{
			name:     "Negative means no limit",
			seconds:  -1,
			expected: noLimit,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatTimeout(tt.seconds)
			if result != tt.expected {
				t.Errorf("formatTimeout(%d) = %s, want %s", tt.seconds, result, tt.expected)
			}
		})
	}
}

func TestFormatCount(t *testing.T) {
	tests := []struct {
		name     string
		count    int
		expected string
	}{
		{
			name:     "Positive count",
			count:    12,
			expected: "12",
		},
		{
			name:     "Zero means no limit",
			count:    0,
			expected: noLimit,
		},
		{
			name:     "Negative means no limit",
			count:    -1,
			expected: noLimit,
		},
		{
			name:     "Large count",
			count:    9999,
			expected: "9999",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatCount(tt.count)
			if result != tt.expected {
				t.Errorf("formatCount(%d) = %s, want %s", tt.count, result, tt.expected)
			}
		})
	}
}

func TestFormatConfigLine(t *testing.T) {
	tests := []struct {
		name     string
		label    string
		value    any
		contains []string
	}{
		{
			name:  "String value",
			label: "Token Name",
			value: "sa-token",
			contains: []string{
				"Token Name",
				"sa-token",
				"│",
			},
		},
		{
			name:  "Boolean value",
			label: "Auto Renew",
			value: true,
			contains: []string{
				"Auto Renew",
				"true",
			},
		},
		{
			name:  "Integer value",
			label: "Max Count",
			value: 12,
			contains: []string{
				"Max Count",
				"12",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatConfigLine(tt.label, tt.value)
			for _, s := range tt.contains {
				if !strings.Contains(result, s) {
					t.Errorf("formatConfigLine(%s, %v) should contain %s, got: %s", tt.label, tt.value, s, result)
				}
			}
		})
	}
}

func TestPrintWithConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   *config.Config
		contains []string
	}{
		{
			name:   "Default configuration",
			config: config.DefaultConfig(),
			contains: []string{
				"Configuration",
				"Token Name",
				"satoken",
				"Token Style",
				"uuid",
				"Token Timeout",
				"30 days",
				"Auto Renew",
				"Concurrent",
				"Share Token",
				"Max Login Count",
				"Read From",
				"Header",
				"Cookie MaxAge",
				"Cookie Secure",
				"Cookie HttpOnly",
			},
		},
		{
			name: "JWT configuration",
			config: &config.Config{
				TokenName:     "jwt-token",
				Timeout:       3600,
				ActiveTimeout: -1,
				IsConcurrent:  true,
				IsShare:       false,
				MaxLoginCount: 5,
				IsReadBody:    false,
				IsReadHeader:  true,
				IsReadCookie:  false,
				TokenStyle:    config.TokenStyleJWT,
				AutoRenew:     true,
				JwtSecretKey:  "my-secret-key",
				IsLog:         true,
				CookieConfig: &config.CookieConfig{
					Path:     "/api",
					SameSite: config.SameSiteLax,
					HttpOnly: true,
					Secure:   true,
				},
			},
			contains: []string{
				"jwt-token",
				"jwt",
				"3600 seconds",
				"JWT Secret Key",
				"*** (configured)",
				"Cookie MaxAge",
				"Cookie HttpOnly",
				"Cookie Secure",
			},
		},
		{
			name: "Never expire configuration",
			config: &config.Config{
				TokenName:     "never-token",
				Timeout:       0,
				ActiveTimeout: -1,
				IsConcurrent:  false,
				IsShare:       true,
				MaxLoginCount: -1,
				TokenStyle:    config.TokenStyleUUID,
				CookieConfig:  &config.CookieConfig{},
			},
			contains: []string{
				"Never Expire",
				"No Limit",
			},
		},
		{
			name: "JWT without secret key",
			config: &config.Config{
				TokenName:    "jwt-token",
				TokenStyle:   config.TokenStyleJWT,
				JwtSecretKey: "",
				CookieConfig: &config.CookieConfig{},
			},
			contains: []string{
				"JWT Secret Key",
				"*** (configured)",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureOutput(func() {
				PrintWithConfig(tt.config)
			})

			for _, s := range tt.contains {
				if !strings.Contains(output, s) {
					t.Errorf("PrintWithConfig() output should contain '%s'\nGot output:\n%s", s, output)
				}
			}

			// Check for box drawing characters
			if !strings.Contains(output, "┌") || !strings.Contains(output, "└") {
				t.Error("Output should contain box drawing characters")
			}
		})
	}
}

func TestPrintWithConfigNilCookie(t *testing.T) {
	cfg := &config.Config{
		TokenName:    "test-token",
		TokenStyle:   config.TokenStyleSimple,
		CookieConfig: nil, // nil cookie config
	}

	output := captureOutput(func() {
		PrintWithConfig(cfg)
	})

	// Should not panic and should not contain cookie configuration
	if strings.Contains(output, "Cookie Path") {
		t.Error("Output should not contain Cookie configuration when CookieConfig is nil")
	}
}

func BenchmarkPrint(b *testing.B) {
	// Redirect output to discard
	old := os.Stdout
	os.Stdout, _ = os.Open(os.DevNull)
	defer func() { os.Stdout = old }()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Print()
	}
}

func BenchmarkPrintWithConfig(b *testing.B) {
	cfg := config.DefaultConfig()

	// Redirect output to discard
	old := os.Stdout
	os.Stdout, _ = os.Open(os.DevNull)
	defer func() { os.Stdout = old }()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PrintWithConfig(cfg)
	}
}

func BenchmarkFormatTimeout(b *testing.B) {
	for i := 0; i < b.N; i++ {
		formatTimeout(2592000)
	}
}

func BenchmarkFormatCount(b *testing.B) {
	for i := 0; i < b.N; i++ {
		formatCount(12)
	}
}

func BenchmarkFormatConfigLine(b *testing.B) {
	for i := 0; i < b.N; i++ {
		formatConfigLine("Token Name", "sa-token")
	}
}

// TestPrintWithConfigVisual is a visual test that prints the full banner and config to stdout.
// It does not assert anything — useful for manual inspection during development.
func TestPrintWithConfigVisual(t *testing.T) {
	t.Log("=== Visual Output of PrintWithConfig (Default Config) ===")
	PrintWithConfig(config.DefaultConfig())
	t.Log("=== End of Visual Output ===")
}
