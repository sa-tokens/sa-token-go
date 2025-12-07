// @Author daixk 2025/12/6 16:47:00
package config

import (
	"github.com/click33/sa-token-go/core/pool"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

// TestDefaultConfig verifies that DefaultConfig returns a valid configuration | 验证 DefaultConfig 返回的配置是否合法
func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	assert.NotNil(t, cfg)
	assert.Equal(t, DefaultTokenName, cfg.TokenName)
	assert.Equal(t, DefaultKeyPrefix, cfg.KeyPrefix)
	assert.True(t, cfg.TokenStyle.IsValid())

	err := cfg.Validate()
	assert.NoError(t, err)
}

// TestInvalidTokenStyle checks invalid TokenStyle detection | 检查无效 TokenStyle 的检测
func TestInvalidTokenStyle(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TokenStyle = "invalid-style"
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid TokenStyle")
}

// TestJwtSecretKeyValidation checks that JWT style requires secret key | 检查 JWT 风格必须设置密钥
func TestJwtSecretKeyValidation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TokenStyle = TokenStyleJWT
	cfg.JwtSecretKey = ""
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "JwtSecretKey is required")
}

// TestNumericLimitValidation checks NoLimit and invalid numeric values | 检查数值字段 NoLimit 与非法值
func TestNumericLimitValidation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Timeout = 0 // invalid
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Timeout")

	cfg.Timeout = NoLimit
	cfg.MaxRefresh = 10
	cfg.RenewInterval = 5
	err = cfg.Validate()
	assert.NoError(t, err)
}

// TestCookieValidation checks cookie path and samesite validation | 检查 Cookie 路径与 SameSite 校验
func TestCookieValidation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CookieConfig.Path = ""
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "CookieConfig.Path")

	cfg.CookieConfig.Path = "/"
	cfg.CookieConfig.SameSite = "Invalid"
	err = cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid CookieConfig.SameSite")
}

// TestRenewPoolValidation checks renew pool config validation | 检查续期池配置验证逻辑
func TestRenewPoolValidation(t *testing.T) {
	cfg := DefaultConfig()
	poolCfg := pool.DefaultRenewPoolConfig()
	poolCfg.MinSize = 0
	cfg.RenewPoolConfig = poolCfg
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be > 0")

	poolCfg.MinSize = 1
	poolCfg.MaxSize = 0
	cfg.RenewPoolConfig = poolCfg
	err = cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be >=")

	poolCfg.MaxSize = 10
	poolCfg.ScaleUpRate = 2
	cfg.RenewPoolConfig = poolCfg
	err = cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ScaleUpRate")

	poolCfg.ScaleUpRate = 0.5
	poolCfg.ScaleDownRate = -0.2
	cfg.RenewPoolConfig = poolCfg
	err = cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ScaleDownRate")

	poolCfg.ScaleDownRate = 0.5
	poolCfg.CheckInterval = 0
	cfg.RenewPoolConfig = poolCfg
	err = cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "CheckInterval")

	poolCfg.CheckInterval = 5 * time.Second
	poolCfg.Expiry = 0
	cfg.RenewPoolConfig = poolCfg
	err = cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Expiry")

	// Valid pool config
	poolCfg.Expiry = 10 * time.Second
	cfg.RenewPoolConfig = poolCfg
	err = cfg.Validate()
	assert.NoError(t, err)
}

// TestKeyPrefixValidation checks key prefix length and whitespace | 检查 KeyPrefix 长度与空白字符
func TestKeyPrefixValidation(t *testing.T) {
	cfg := DefaultConfig()

	cfg.KeyPrefix = "with space "
	err := cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "whitespace")

	longPrefix := make([]byte, 70)
	for i := range longPrefix {
		longPrefix[i] = 'a'
	}
	cfg.KeyPrefix = string(longPrefix)
	err = cfg.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too long")
}

// TestClone verifies deep copy behavior | 验证 Clone 的深拷贝行为
func TestClone(t *testing.T) {
	cfg := DefaultConfig()
	clone := cfg.Clone()
	assert.Equal(t, cfg.TokenName, clone.TokenName)

	// Modify original cookie
	cfg.CookieConfig.Path = "/changed"
	assert.NotEqual(t, cfg.CookieConfig.Path, clone.CookieConfig.Path)

	// Modify renew pool
	cfg.RenewPoolConfig.MinSize = 99
	assert.NotEqual(t, cfg.RenewPoolConfig.MinSize, clone.RenewPoolConfig.MinSize)
}

// TestSetters verifies chainable setter behavior | 验证所有 setter 的链式调用行为
func TestSetters(t *testing.T) {
	cfg := DefaultConfig().
		SetTokenName("mytoken").
		SetTimeout(100).
		SetMaxRefresh(50).
		SetRenewInterval(10).
		SetActiveTimeout(5).
		SetIsConcurrent(false).
		SetIsShare(false).
		SetMaxLoginCount(2).
		SetIsReadBody(true).
		SetIsReadHeader(false).
		SetIsReadCookie(true).
		SetTokenStyle(TokenStyleRandom64).
		SetTokenSessionCheckLogin(false).
		SetJwtSecretKey("secret").
		SetAutoRenew(false).
		SetIsLog(true).
		SetIsPrintBanner(false).
		SetKeyPrefix("prefix:")

	assert.Equal(t, "mytoken", cfg.TokenName)
	assert.Equal(t, int64(100), cfg.Timeout)
	assert.Equal(t, TokenStyleRandom64, cfg.TokenStyle)
	assert.Equal(t, false, cfg.IsConcurrent)
	assert.Equal(t, "prefix:", cfg.KeyPrefix)
}

// TestAdjustMaxRefresh verifies automatic adjustment of MaxRefresh | 验证 MaxRefresh 自动调整逻辑
func TestAdjustMaxRefresh(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Timeout = 10
	cfg.MaxRefresh = 100
	err := cfg.Validate()
	assert.NoError(t, err)
	assert.Equal(t, int64(5), cfg.MaxRefresh) // adjusted to Timeout/2
}
