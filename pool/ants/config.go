// @Author daixk 2025/12/22 15:56:00
package ants

import (
	"fmt"
	"time"
)

// RenewPoolConfig configuration for the renewal pool manager | 续期池配置
type RenewPoolConfig struct {
	MinSize             int           // Minimum pool size | 最小协程数
	MaxSize             int           // Maximum pool size | 最大协程数
	ScaleUpRate         float64       // Scale-up threshold | 扩容阈值
	ScaleDownRate       float64       // Scale-down threshold | 缩容阈值
	CheckInterval       time.Duration // Auto-scale check interval | 检查间隔
	Expiry              time.Duration // Idle worker expiry duration | 空闲协程过期时间
	PrintStatusInterval time.Duration // Interval for periodic status printing (0 = disabled) | 定时打印池状态的间隔（0表示关闭）
	PreAlloc            bool          // Whether to pre-allocate memory | 是否预分配内存
	NonBlocking         bool          // Whether to use non-blocking mode | 是否为非阻塞模式
}

// DefaultRenewPoolConfig returns default renew pool config | 返回默认续期池配置
func DefaultRenewPoolConfig() *RenewPoolConfig {
	return &RenewPoolConfig{
		MinSize:       DefaultMinSize,
		MaxSize:       DefaultMaxSize,
		ScaleUpRate:   DefaultScaleUpRate,
		ScaleDownRate: DefaultScaleDownRate,
		CheckInterval: DefaultCheckInterval,
		Expiry:        DefaultExpiry,
		PreAlloc:      false,
		NonBlocking:   true,
	}
}

// Validate validates renew pool configuration | 验证续期池配置合法性
func (c *RenewPoolConfig) Validate() error {
	if c == nil {
		return nil // Nil config is allowed | 允许未配置续期池
	}

	if c.MinSize <= 0 {
		return fmt.Errorf("RenewPoolConfig.MinSize must be > 0")
	}
	if c.MaxSize < c.MinSize {
		return fmt.Errorf("RenewPoolConfig.MaxSize must be >= RenewPoolConfig.MinSize")
	}

	if c.ScaleUpRate <= 0 || c.ScaleUpRate > 1 {
		return fmt.Errorf("RenewPoolConfig.ScaleUpRate must be between 0 and 1")
	}
	if c.ScaleDownRate < 0 || c.ScaleDownRate > 1 {
		return fmt.Errorf("RenewPoolConfig.ScaleDownRate must be between 0 and 1")
	}

	if c.CheckInterval <= 0 {
		return fmt.Errorf("RenewPoolConfig.CheckInterval must be a positive duration")
	}
	if c.Expiry <= 0 {
		return fmt.Errorf("RenewPoolConfig.Expiry must be a positive duration")
	}

	return nil
}

// Clone returns a deep copy of the renew pool config | 克隆续期池配置
func (c *RenewPoolConfig) Clone() *RenewPoolConfig {
	if c == nil {
		return nil
	}
	copyCfg := *c
	return &copyCfg
}

// SetMinSize sets minimum pool size | 设置最小协程数
func (c *RenewPoolConfig) SetMinSize(size int) *RenewPoolConfig {
	c.MinSize = size
	return c
}

// SetMaxSize sets maximum pool size | 设置最大协程数
func (c *RenewPoolConfig) SetMaxSize(size int) *RenewPoolConfig {
	c.MaxSize = size
	return c
}

// SetScaleUpRate sets scale-up threshold | 设置扩容阈值
func (c *RenewPoolConfig) SetScaleUpRate(up float64) *RenewPoolConfig {
	c.ScaleUpRate = up
	return c
}

// SetScaleDownRate sets scale-down threshold | 设置缩容阈值
func (c *RenewPoolConfig) SetScaleDownRate(down float64) *RenewPoolConfig {
	c.ScaleDownRate = down
	return c
}

// SetCheckInterval sets auto-scaling check interval | 设置检查间隔
func (c *RenewPoolConfig) SetCheckInterval(interval time.Duration) *RenewPoolConfig {
	c.CheckInterval = interval
	return c
}

// SetExpiry sets worker expiry duration | 设置空闲协程过期时间
func (c *RenewPoolConfig) SetExpiry(expiry time.Duration) *RenewPoolConfig {
	c.Expiry = expiry
	return c
}

// SetPrintStatusInterval sets status print interval | 设置打印状态的间隔
func (c *RenewPoolConfig) SetPrintStatusInterval(interval time.Duration) *RenewPoolConfig {
	c.PrintStatusInterval = interval
	return c
}

// SetPreAlloc sets pre-allocation flag | 设置是否预分配内存
func (c *RenewPoolConfig) SetPreAlloc(prealloc bool) *RenewPoolConfig {
	c.PreAlloc = prealloc
	return c
}

// SetNonBlocking sets non-blocking mode | 设置是否非阻塞模式
func (c *RenewPoolConfig) SetNonBlocking(nonblocking bool) *RenewPoolConfig {
	c.NonBlocking = nonblocking
	return c
}
