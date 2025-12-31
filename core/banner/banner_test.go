package banner

import (
	"testing"

	"github.com/click33/sa-token-go/core/adapter"
	"github.com/click33/sa-token-go/core/config"
)

// TestPrintWithConfig_Default tests banner printing with default configuration
func TestPrintWithConfig_Default(t *testing.T) {
	t.Log("=== Testing with Default Config ===")
	cfg := config.DefaultConfig()
	PrintWithConfig(cfg)
}

// TestPrintWithConfig_JWT tests banner printing with JWT configuration
func TestPrintWithConfig_JWT(t *testing.T) {
	t.Log("=== Testing with JWT Config ===")
	cfg := config.DefaultConfig()
	cfg.SetTokenStyle(adapter.TokenStyleJWT)
	cfg.SetJwtSecretKey("my-secret-key-123456")
	cfg.SetTimeout(86400)      // 1 day
	cfg.SetActiveTimeout(3600) // 1 hour
	cfg.SetAutoRenew(true)
	cfg.SetMaxRefresh(43200) // 12 hours
	PrintWithConfig(cfg)
}

// TestPrintWithConfig_NonConcurrent tests banner printing with non-concurrent login
func TestPrintWithConfig_NonConcurrent(t *testing.T) {
	t.Log("=== Testing with Non-Concurrent Login Config ===")
	cfg := config.DefaultConfig()
	cfg.SetIsConcurrent(false)
	cfg.SetIsShare(false)
	PrintWithConfig(cfg)
}

// TestPrintWithConfig_MaxLoginCount tests banner printing with max login count
func TestPrintWithConfig_MaxLoginCount(t *testing.T) {
	t.Log("=== Testing with Max Login Count Config ===")
	cfg := config.DefaultConfig()
	cfg.SetIsConcurrent(true)
	cfg.SetIsShare(false)
	cfg.SetMaxLoginCount(5)
	PrintWithConfig(cfg)
}

// TestPrintWithConfig_AllReadSources tests banner printing with all read sources enabled
func TestPrintWithConfig_AllReadSources(t *testing.T) {
	t.Log("=== Testing with All Read Sources Enabled ===")
	cfg := config.DefaultConfig()
	cfg.SetIsReadHeader(true)
	cfg.SetIsReadCookie(true)
	cfg.SetIsReadBody(true)
	PrintWithConfig(cfg)
}

// TestPrintWithConfig_CustomPrefix tests banner printing with custom prefix and auth type
func TestPrintWithConfig_CustomPrefix(t *testing.T) {
	t.Log("=== Testing with Custom Prefix and Auth Type ===")
	cfg := config.DefaultConfig()
	cfg.SetKeyPrefix("myapp")
	cfg.SetAuthType("oauth2")
	cfg.SetTokenName("access_token")
	PrintWithConfig(cfg)
}

// TestPrintWithConfig_NoAutoRenew tests banner printing without auto renew
func TestPrintWithConfig_NoAutoRenew(t *testing.T) {
	t.Log("=== Testing without Auto Renew ===")
	cfg := config.DefaultConfig()
	cfg.SetAutoRenew(false)
	PrintWithConfig(cfg)
}

// TestPrintWithConfig_NeverExpire tests banner printing with never expire timeout
func TestPrintWithConfig_NeverExpire(t *testing.T) {
	t.Log("=== Testing with Never Expire Timeout ===")
	cfg := config.DefaultConfig()
	cfg.SetTimeout(-1)
	cfg.SetActiveTimeout(-1)
	PrintWithConfig(cfg)
}

// TestPrintWithConfig_LongTimeout tests banner printing with long timeout (shows days)
func TestPrintWithConfig_LongTimeout(t *testing.T) {
	t.Log("=== Testing with Long Timeout (30 days) ===")
	cfg := config.DefaultConfig()
	cfg.SetTimeout(2592000)      // 30 days
	cfg.SetActiveTimeout(604800) // 7 days
	cfg.SetMaxRefresh(1296000)   // 15 days
	PrintWithConfig(cfg)
}

// TestPrint tests basic banner printing
func TestPrint(t *testing.T) {
	t.Log("=== Testing Basic Banner ===")
	Print()
}
