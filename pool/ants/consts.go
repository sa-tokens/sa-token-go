// @Author daixk 2025/12/22 15:56:00
package ants

import "time"

// Default configuration constants | 默认配置常量
const (
	DefaultMinSize       = 100              // Minimum pool size | 最小协程数
	DefaultMaxSize       = 2000             // Maximum pool size | 最大协程数
	DefaultScaleUpRate   = 0.8              // Scale-up threshold | 扩容阈值
	DefaultScaleDownRate = 0.3              // Scale-down threshold | 缩容阈值
	DefaultCheckInterval = time.Minute      // Interval for auto-scaling checks | 检查间隔
	DefaultExpiry        = 10 * time.Second // Idle worker expiry duration | 空闲协程过期时间
)
