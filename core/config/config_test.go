package config

import (
	"strings"
	"testing"

	"github.com/click33/sa-token-go/core/adapter"
)

// =============== Phase 1: Basic format validation tests | 阶段1：基础格式验证测试 ===============

// TestValidate_TokenName tests TokenName validation
func TestValidate_TokenName(t *testing.T) {
	tests := []struct {
		name      string
		tokenName string
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "Valid TokenName",
			tokenName: "satoken",
			wantErr:   false,
		},
		{
			name:      "Valid TokenName with hyphen",
			tokenName: "sa-token",
			wantErr:   false,
		},
		{
			name:      "Valid TokenName with underscore",
			tokenName: "sa_token",
			wantErr:   false,
		},
		{
			name:      "Empty TokenName should error",
			tokenName: "",
			wantErr:   true,
			errMsg:    "cannot be empty",
		},
		{
			name:      "TokenName with tab should error",
			tokenName: "sa\ttoken",
			wantErr:   true,
			errMsg:    "tab/newline",
		},
		{
			name:      "TokenName with newline should error",
			tokenName: "sa\ntoken",
			wantErr:   true,
			errMsg:    "tab/newline",
		},
		{
			name:      "TokenName with carriage return should error",
			tokenName: "sa\rtoken",
			wantErr:   true,
			errMsg:    "tab/newline",
		},
		{
			name:      "TokenName too long should error",
			tokenName: strings.Repeat("a", 65),
			wantErr:   true,
			errMsg:    "too long",
		},
		{
			name:      "TokenName at max length should pass",
			tokenName: strings.Repeat("a", 64),
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.TokenName = tt.tokenName
			err := cfg.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error containing %q, got nil", tt.errMsg)
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

// TestValidate_KeyPrefix tests KeyPrefix validation
func TestValidate_KeyPrefix(t *testing.T) {
	tests := []struct {
		name      string
		keyPrefix string
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "Valid KeyPrefix",
			keyPrefix: "satoken:",
			wantErr:   false,
		},
		{
			name:      "Valid KeyPrefix with colon",
			keyPrefix: "app:satoken:",
			wantErr:   false,
		},
		{
			name:      "Empty KeyPrefix should error",
			keyPrefix: "",
			wantErr:   true,
			errMsg:    "cannot be empty",
		},
		{
			name:      "KeyPrefix with tab should error",
			keyPrefix: "sa\ttoken:",
			wantErr:   true,
			errMsg:    "tab/newline",
		},
		{
			name:      "KeyPrefix with newline should error",
			keyPrefix: "sa\ntoken:",
			wantErr:   true,
			errMsg:    "tab/newline",
		},
		{
			name:      "KeyPrefix too long should error",
			keyPrefix: strings.Repeat("a", 65),
			wantErr:   true,
			errMsg:    "too long",
		},
		{
			name:      "KeyPrefix at max length should pass",
			keyPrefix: strings.Repeat("a", 64),
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.KeyPrefix = tt.keyPrefix
			err := cfg.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error containing %q, got nil", tt.errMsg)
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

// TestValidate_AuthType tests AuthType validation
func TestValidate_AuthType(t *testing.T) {
	tests := []struct {
		name     string
		authType string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "Valid AuthType",
			authType: "login",
			wantErr:  false,
		},
		{
			name:     "Empty AuthType should error",
			authType: "",
			wantErr:  true,
			errMsg:   "cannot be empty",
		},
		{
			name:     "AuthType with tab should error",
			authType: "auth\ttype",
			wantErr:  true,
			errMsg:   "tab/newline",
		},
		{
			name:     "AuthType too long should error",
			authType: strings.Repeat("a", 65),
			wantErr:  true,
			errMsg:   "too long",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.AuthType = tt.authType
			err := cfg.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error containing %q, got nil", tt.errMsg)
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

// =============== Phase 2: Numeric range validation tests | 阶段2：数值范围验证测试 ===============

// TestValidate_NumericFields tests numeric field validation
func TestValidate_NumericFields(t *testing.T) {
	tests := []struct {
		name      string
		fieldName string
		setValue  func(*Config, int64)
		value     int64
		wantErr   bool
	}{
		// Timeout tests
		{"Timeout valid positive", "Timeout", func(c *Config, v int64) { c.Timeout = v }, 3600, false},
		{"Timeout NoLimit", "Timeout", func(c *Config, v int64) { c.Timeout = v }, NoLimit, false},
		{"Timeout zero should error", "Timeout", func(c *Config, v int64) { c.Timeout = v }, 0, true},
		{"Timeout negative should error", "Timeout", func(c *Config, v int64) { c.Timeout = v }, -2, true},

		// MaxRefresh tests
		{"MaxRefresh valid positive", "MaxRefresh", func(c *Config, v int64) { c.MaxRefresh = v }, 1800, false},
		{"MaxRefresh NoLimit", "MaxRefresh", func(c *Config, v int64) { c.MaxRefresh = v }, NoLimit, false},
		{"MaxRefresh zero should error", "MaxRefresh", func(c *Config, v int64) { c.MaxRefresh = v }, 0, true},

		// RenewInterval tests
		{"RenewInterval valid positive", "RenewInterval", func(c *Config, v int64) { c.RenewInterval = v }, 60, false},
		{"RenewInterval NoLimit", "RenewInterval", func(c *Config, v int64) { c.RenewInterval = v }, NoLimit, false},
		{"RenewInterval zero should error", "RenewInterval", func(c *Config, v int64) { c.RenewInterval = v }, 0, true},

		// ActiveTimeout tests
		{"ActiveTimeout valid positive", "ActiveTimeout", func(c *Config, v int64) { c.ActiveTimeout = v }, 1800, false},
		{"ActiveTimeout NoLimit", "ActiveTimeout", func(c *Config, v int64) { c.ActiveTimeout = v }, NoLimit, false},
		{"ActiveTimeout zero should error", "ActiveTimeout", func(c *Config, v int64) { c.ActiveTimeout = v }, 0, true},

		// MaxLoginCount tests
		{"MaxLoginCount valid positive", "MaxLoginCount", func(c *Config, v int64) { c.MaxLoginCount = v }, 5, false},
		{"MaxLoginCount NoLimit", "MaxLoginCount", func(c *Config, v int64) { c.MaxLoginCount = v }, NoLimit, false},
		{"MaxLoginCount zero should error", "MaxLoginCount", func(c *Config, v int64) { c.MaxLoginCount = v }, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.setValue(cfg, tt.value)
			err := cfg.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error for %s=%d, got nil", tt.fieldName, tt.value)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for %s=%d, got %v", tt.fieldName, tt.value, err)
				}
			}
		})
	}
}

// =============== Phase 3: TokenStyle + JWT validation tests | 阶段3：Token风格验证测试 ===============

// TestValidate_TokenStyle tests TokenStyle validation
func TestValidate_TokenStyle(t *testing.T) {
	tests := []struct {
		name       string
		tokenStyle adapter.TokenStyle
		jwtSecret  string
		wantErr    bool
		errMsg     string
	}{
		{
			name:       "Valid UUID style",
			tokenStyle: adapter.TokenStyleUUID,
			wantErr:    false,
		},
		{
			name:       "Valid Simple style",
			tokenStyle: adapter.TokenStyleSimple,
			wantErr:    false,
		},
		{
			name:       "Valid Random32 style",
			tokenStyle: adapter.TokenStyleRandom32,
			wantErr:    false,
		},
		{
			name:       "Valid Random64 style",
			tokenStyle: adapter.TokenStyleRandom64,
			wantErr:    false,
		},
		{
			name:       "Valid Random128 style",
			tokenStyle: adapter.TokenStyleRandom128,
			wantErr:    false,
		},
		{
			name:       "Valid JWT style with secret",
			tokenStyle: adapter.TokenStyleJWT,
			jwtSecret:  "my-secret-key",
			wantErr:    false,
		},
		{
			name:       "JWT style without secret should error",
			tokenStyle: adapter.TokenStyleJWT,
			jwtSecret:  "",
			wantErr:    true,
			errMsg:     "JwtSecretKey is required",
		},
		{
			name:       "Invalid TokenStyle should error",
			tokenStyle: adapter.TokenStyle("invalid"),
			wantErr:    true,
			errMsg:     "invalid TokenStyle",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.TokenStyle = tt.tokenStyle
			cfg.JwtSecretKey = tt.jwtSecret
			err := cfg.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error containing %q, got nil", tt.errMsg)
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

// =============== Phase 4: Auto-adjustment tests | 阶段4：自动调整测试 ===============

// TestValidate_AutoAdjustMaxRefresh tests auto-adjustment of MaxRefresh
func TestValidate_AutoAdjustMaxRefresh(t *testing.T) {
	tests := []struct {
		name               string
		timeout            int64
		maxRefresh         int64
		autoRenew          bool
		expectedMaxRefresh int64
	}{
		{
			name:               "MaxRefresh exceeds Timeout - should adjust to Timeout/2",
			timeout:            3600,
			maxRefresh:         7200,
			autoRenew:          true,
			expectedMaxRefresh: 1800,
		},
		{
			name:               "MaxRefresh within Timeout - should not change",
			timeout:            3600,
			maxRefresh:         1800,
			autoRenew:          true,
			expectedMaxRefresh: 1800,
		},
		{
			name:               "AutoRenew disabled - should not adjust",
			timeout:            3600,
			maxRefresh:         7200,
			autoRenew:          false,
			expectedMaxRefresh: 7200,
		},
		{
			name:               "Timeout is NoLimit - should not adjust",
			timeout:            NoLimit,
			maxRefresh:         7200,
			autoRenew:          true,
			expectedMaxRefresh: 7200,
		},
		{
			name:               "MaxRefresh is NoLimit - should not adjust",
			timeout:            3600,
			maxRefresh:         NoLimit,
			autoRenew:          true,
			expectedMaxRefresh: NoLimit,
		},
		{
			name:               "Very small Timeout - MaxRefresh should equal Timeout",
			timeout:            1,
			maxRefresh:         3600,
			autoRenew:          true,
			expectedMaxRefresh: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Timeout = tt.timeout
			cfg.MaxRefresh = tt.maxRefresh
			cfg.AutoRenew = tt.autoRenew

			err := cfg.Validate()
			if err != nil {
				t.Fatalf("Validate() error = %v, want nil", err)
			}

			if cfg.MaxRefresh != tt.expectedMaxRefresh {
				t.Errorf("MaxRefresh = %d, want %d", cfg.MaxRefresh, tt.expectedMaxRefresh)
			}
		})
	}
}

// =============== Phase 5: Time relationship validation tests | 阶段5：时间关系验证测试 ===============

// TestValidate_RenewIntervalVsActiveTimeout tests RenewInterval vs ActiveTimeout validation
func TestValidate_RenewIntervalVsActiveTimeout(t *testing.T) {
	tests := []struct {
		name          string
		autoRenew     bool
		activeTimeout int64
		renewInterval int64
		wantErr       bool
	}{
		{
			name:          "RenewInterval < ActiveTimeout - should pass",
			autoRenew:     true,
			activeTimeout: 3600,
			renewInterval: 1800,
			wantErr:       false,
		},
		{
			name:          "RenewInterval = ActiveTimeout - should error",
			autoRenew:     true,
			activeTimeout: 3600,
			renewInterval: 3600,
			wantErr:       true,
		},
		{
			name:          "RenewInterval > ActiveTimeout - should error",
			autoRenew:     true,
			activeTimeout: 1800,
			renewInterval: 3600,
			wantErr:       true,
		},
		{
			name:          "AutoRenew disabled - should pass even if RenewInterval >= ActiveTimeout",
			autoRenew:     false,
			activeTimeout: 1800,
			renewInterval: 3600,
			wantErr:       false,
		},
		{
			name:          "ActiveTimeout is NoLimit - should pass",
			autoRenew:     true,
			activeTimeout: NoLimit,
			renewInterval: 3600,
			wantErr:       false,
		},
		{
			name:          "RenewInterval is NoLimit - should pass",
			autoRenew:     true,
			activeTimeout: 3600,
			renewInterval: NoLimit,
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.AutoRenew = tt.autoRenew
			cfg.ActiveTimeout = tt.activeTimeout
			cfg.RenewInterval = tt.renewInterval

			err := cfg.Validate()
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

// =============== Phase 6: Token read source validation tests | 阶段6：Token读取来源验证测试 ===============

// TestValidate_TokenReadSources tests token read source validation
func TestValidate_TokenReadSources(t *testing.T) {
	tests := []struct {
		name         string
		isReadHeader bool
		isReadCookie bool
		isReadBody   bool
		wantErr      bool
	}{
		{
			name:         "Only Header enabled",
			isReadHeader: true,
			isReadCookie: false,
			isReadBody:   false,
			wantErr:      false,
		},
		{
			name:         "Only Cookie enabled",
			isReadHeader: false,
			isReadCookie: true,
			isReadBody:   false,
			wantErr:      false,
		},
		{
			name:         "Only Body enabled",
			isReadHeader: false,
			isReadCookie: false,
			isReadBody:   true,
			wantErr:      false,
		},
		{
			name:         "All enabled",
			isReadHeader: true,
			isReadCookie: true,
			isReadBody:   true,
			wantErr:      false,
		},
		{
			name:         "None enabled - should error",
			isReadHeader: false,
			isReadCookie: false,
			isReadBody:   false,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.IsReadHeader = tt.isReadHeader
			cfg.IsReadCookie = tt.isReadCookie
			cfg.IsReadBody = tt.isReadBody

			err := cfg.Validate()
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

// =============== Phase 7: CookieConfig validation tests | 阶段7：Cookie配置验证测试 ===============

// TestValidate_CookieConfig tests CookieConfig validation
func TestValidate_CookieConfig(t *testing.T) {
	tests := []struct {
		name         string
		isReadCookie bool
		cookieConfig *CookieConfig
		wantErr      bool
		errMsg       string
	}{
		{
			name:         "Valid CookieConfig with IsReadCookie=true",
			isReadCookie: true,
			cookieConfig: DefaultCookieConfig(),
			wantErr:      false,
		},
		{
			name:         "Nil CookieConfig with IsReadCookie=true - should error",
			isReadCookie: true,
			cookieConfig: nil,
			wantErr:      true,
			errMsg:       "CookieConfig cannot be nil",
		},
		{
			name:         "Nil CookieConfig with IsReadCookie=false - should pass",
			isReadCookie: false,
			cookieConfig: nil,
			wantErr:      false,
		},
		{
			name:         "Empty Path - should error",
			isReadCookie: true,
			cookieConfig: &CookieConfig{Path: "", SameSite: SameSiteLax},
			wantErr:      true,
			errMsg:       "Path cannot be empty",
		},
		{
			name:         "Valid SameSite Lax",
			isReadCookie: true,
			cookieConfig: &CookieConfig{Path: "/", SameSite: SameSiteLax},
			wantErr:      false,
		},
		{
			name:         "Valid SameSite Strict",
			isReadCookie: true,
			cookieConfig: &CookieConfig{Path: "/", SameSite: SameSiteStrict},
			wantErr:      false,
		},
		{
			name:         "Valid SameSite None with Secure=true",
			isReadCookie: true,
			cookieConfig: &CookieConfig{Path: "/", SameSite: SameSiteNone, Secure: true},
			wantErr:      false,
		},
		{
			name:         "SameSite None with Secure=false - should error",
			isReadCookie: true,
			cookieConfig: &CookieConfig{Path: "/", SameSite: SameSiteNone, Secure: false},
			wantErr:      true,
			errMsg:       "Secure must be true when SameSite is None",
		},
		{
			name:         "Invalid SameSite value - should error",
			isReadCookie: true,
			cookieConfig: &CookieConfig{Path: "/", SameSite: SameSiteMode("Invalid")},
			wantErr:      true,
			errMsg:       "invalid CookieConfig.SameSite",
		},
		{
			name:         "Empty SameSite - should pass (browser default)",
			isReadCookie: true,
			cookieConfig: &CookieConfig{Path: "/", SameSite: ""},
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.IsReadCookie = tt.isReadCookie
			cfg.CookieConfig = tt.cookieConfig

			err := cfg.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error containing %q, got nil", tt.errMsg)
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

// =============== Clone tests | Clone测试 ===============

// TestConfig_Clone tests configuration cloning
func TestConfig_Clone(t *testing.T) {
	t.Run("Clone creates independent copy", func(t *testing.T) {
		original := DefaultConfig()
		original.Timeout = 3600
		original.TokenName = "custom-token"

		cloned := original.Clone()

		// Verify values are copied
		if cloned.Timeout != original.Timeout {
			t.Errorf("Cloned Timeout = %d, want %d", cloned.Timeout, original.Timeout)
		}
		if cloned.TokenName != original.TokenName {
			t.Errorf("Cloned TokenName = %s, want %s", cloned.TokenName, original.TokenName)
		}

		// Verify it's a deep copy
		cloned.Timeout = 7200
		if cloned.Timeout == original.Timeout {
			t.Error("Clone should be independent of original")
		}
	})

	t.Run("Clone deep copies CookieConfig", func(t *testing.T) {
		original := DefaultConfig()
		original.CookieConfig.Domain = "example.com"

		cloned := original.Clone()

		// Verify CookieConfig is copied
		if cloned.CookieConfig.Domain != original.CookieConfig.Domain {
			t.Errorf("Cloned CookieConfig.Domain = %s, want %s", cloned.CookieConfig.Domain, original.CookieConfig.Domain)
		}

		// Verify CookieConfig is independent
		cloned.CookieConfig.Domain = "other.com"
		if cloned.CookieConfig.Domain == original.CookieConfig.Domain {
			t.Error("Cloned CookieConfig should be independent of original")
		}
	})

	t.Run("Clone handles nil CookieConfig", func(t *testing.T) {
		original := DefaultConfig()
		original.CookieConfig = nil

		cloned := original.Clone()

		if cloned.CookieConfig != nil {
			t.Error("Cloned CookieConfig should be nil when original is nil")
		}
	})
}

// =============== Setter chain tests | 链式设置测试 ===============

// TestConfig_SetterChain tests that setters return *Config for chaining
func TestConfig_SetterChain(t *testing.T) {
	cfg := DefaultConfig().
		SetTokenName("my-token").
		SetTimeout(7200).
		SetMaxRefresh(3600).
		SetRenewInterval(60).
		SetActiveTimeout(1800).
		SetIsConcurrent(true).
		SetIsShare(false).
		SetMaxLoginCount(5).
		SetIsReadBody(true).
		SetIsReadHeader(true).
		SetIsReadCookie(false).
		SetTokenStyle(adapter.TokenStyleSimple).
		SetTokenSessionCheckLogin(true).
		SetJwtSecretKey("secret").
		SetAutoRenew(true).
		SetIsLog(true).
		SetIsPrintBanner(false).
		SetKeyPrefix("app:").
		SetAuthType("login")

	// Verify values
	if cfg.TokenName != "my-token" {
		t.Errorf("TokenName = %s, want my-token", cfg.TokenName)
	}
	if cfg.Timeout != 7200 {
		t.Errorf("Timeout = %d, want 7200", cfg.Timeout)
	}
	if cfg.MaxRefresh != 3600 {
		t.Errorf("MaxRefresh = %d, want 3600", cfg.MaxRefresh)
	}
	if cfg.MaxLoginCount != 5 {
		t.Errorf("MaxLoginCount = %d, want 5", cfg.MaxLoginCount)
	}
	if !cfg.IsReadBody {
		t.Error("IsReadBody should be true")
	}
	if cfg.TokenStyle != adapter.TokenStyleSimple {
		t.Errorf("TokenStyle = %s, want simple", cfg.TokenStyle)
	}
	if !cfg.IsLog {
		t.Error("IsLog should be true")
	}
	if cfg.IsPrintBanner {
		t.Error("IsPrintBanner should be false")
	}
}

// =============== DefaultConfig tests | 默认配置测试 ===============

// TestDefaultConfig tests default configuration values
func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.TokenName != DefaultTokenName {
		t.Errorf("TokenName = %s, want %s", cfg.TokenName, DefaultTokenName)
	}
	if cfg.Timeout != DefaultTimeout {
		t.Errorf("Timeout = %d, want %d", cfg.Timeout, DefaultTimeout)
	}
	if cfg.MaxRefresh != DefaultTimeout/2 {
		t.Errorf("MaxRefresh = %d, want %d", cfg.MaxRefresh, DefaultTimeout/2)
	}
	if cfg.RenewInterval != NoLimit {
		t.Errorf("RenewInterval = %d, want %d", cfg.RenewInterval, NoLimit)
	}
	if cfg.ActiveTimeout != NoLimit {
		t.Errorf("ActiveTimeout = %d, want %d", cfg.ActiveTimeout, NoLimit)
	}
	if !cfg.IsConcurrent {
		t.Error("IsConcurrent should be true by default")
	}
	if !cfg.IsShare {
		t.Error("IsShare should be true by default")
	}
	if cfg.MaxLoginCount != DefaultMaxLoginCount {
		t.Errorf("MaxLoginCount = %d, want %d", cfg.MaxLoginCount, DefaultMaxLoginCount)
	}
	if cfg.IsReadBody {
		t.Error("IsReadBody should be false by default")
	}
	if !cfg.IsReadHeader {
		t.Error("IsReadHeader should be true by default")
	}
	if cfg.IsReadCookie {
		t.Error("IsReadCookie should be false by default")
	}
	if cfg.TokenStyle != adapter.TokenStyleUUID {
		t.Errorf("TokenStyle = %s, want uuid", cfg.TokenStyle)
	}
	if !cfg.TokenSessionCheckLogin {
		t.Error("TokenSessionCheckLogin should be true by default")
	}
	if !cfg.AutoRenew {
		t.Error("AutoRenew should be true by default")
	}
	if cfg.JwtSecretKey != "" {
		t.Errorf("JwtSecretKey should be empty by default, got %s", cfg.JwtSecretKey)
	}
	if cfg.IsLog {
		t.Error("IsLog should be false by default")
	}
	if !cfg.IsPrintBanner {
		t.Error("IsPrintBanner should be true by default")
	}
	if cfg.KeyPrefix != DefaultKeyPrefix {
		t.Errorf("KeyPrefix = %s, want %s", cfg.KeyPrefix, DefaultKeyPrefix)
	}
	if cfg.AuthType != DefaultAuthType {
		t.Errorf("AuthType = %s, want %s", cfg.AuthType, DefaultAuthType)
	}
	if cfg.CookieConfig == nil {
		t.Error("CookieConfig should not be nil by default")
	}
}

// TestDefaultCookieConfig tests default cookie configuration values
func TestDefaultCookieConfig(t *testing.T) {
	cc := DefaultCookieConfig()

	if cc.Domain != "" {
		t.Errorf("Domain = %s, want empty string", cc.Domain)
	}
	if cc.Path != DefaultCookiePath {
		t.Errorf("Path = %s, want %s", cc.Path, DefaultCookiePath)
	}
	if cc.Secure {
		t.Error("Secure should be false by default")
	}
	if !cc.HttpOnly {
		t.Error("HttpOnly should be true by default")
	}
	if cc.SameSite != SameSiteLax {
		t.Errorf("SameSite = %s, want %s", cc.SameSite, SameSiteLax)
	}
	if cc.MaxAge != 0 {
		t.Errorf("MaxAge = %d, want 0", cc.MaxAge)
	}
}

// =============== Integration tests | 集成测试 ===============

// TestValidate_DefaultConfig tests that default config passes validation
func TestValidate_DefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	err := cfg.Validate()
	if err != nil {
		t.Errorf("DefaultConfig should pass validation, got error: %v", err)
	}
}

// TestValidate_RealWorldScenarios tests common real-world configuration scenarios
func TestValidate_RealWorldScenarios(t *testing.T) {
	t.Run("Web application with short session", func(t *testing.T) {
		cfg := DefaultConfig().
			SetTimeout(3600).       // 1 hour
			SetActiveTimeout(1800). // 30 minutes inactive kick
			SetRenewInterval(300).  // renew every 5 minutes max
			SetIsReadCookie(true).
			SetIsReadHeader(true)

		err := cfg.Validate()
		if err != nil {
			t.Errorf("Expected valid config, got error: %v", err)
		}
	})

	t.Run("API service with long-lived tokens", func(t *testing.T) {
		cfg := DefaultConfig().
			SetTimeout(NoLimit).       // never expire
			SetActiveTimeout(NoLimit). // no inactive timeout
			SetIsReadHeader(true).
			SetIsReadCookie(false)

		err := cfg.Validate()
		if err != nil {
			t.Errorf("Expected valid config, got error: %v", err)
		}
	})

	t.Run("JWT based authentication", func(t *testing.T) {
		cfg := DefaultConfig().
			SetTokenStyle(adapter.TokenStyleJWT).
			SetJwtSecretKey("my-super-secret-key-for-jwt-signing").
			SetTimeout(86400) // 1 day

		err := cfg.Validate()
		if err != nil {
			t.Errorf("Expected valid config, got error: %v", err)
		}
	})

	t.Run("Multi-device login support", func(t *testing.T) {
		cfg := DefaultConfig().
			SetIsConcurrent(true).
			SetIsShare(false).
			SetMaxLoginCount(5)

		err := cfg.Validate()
		if err != nil {
			t.Errorf("Expected valid config, got error: %v", err)
		}
	})

	t.Run("Single device login only", func(t *testing.T) {
		cfg := DefaultConfig().
			SetIsConcurrent(false).
			SetIsShare(true) // must be true when IsConcurrent is false

		err := cfg.Validate()
		if err != nil {
			t.Errorf("Expected valid config, got error: %v", err)
		}
	})
}
