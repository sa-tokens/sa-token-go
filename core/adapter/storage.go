package adapter

import (
	"context"
	"time"
)

// Storage defines storage interface for Token and Session data | 定义存储接口，用于存储Token和Session数据
type Storage interface {
	// ============== Basic Operations | 基本操作 ==============

	// Set sets key-value pair with optional expiration time (0 means never expire) | 设置键值对，可选过期时间（0表示永不过期）
	Set(ctx context.Context, key string, value any, expiration time.Duration) error

	// SetKeepTTL sets key-value pair but keeps the original TTL unchanged | 设置键值但保持原有TTL不变
	SetKeepTTL(ctx context.Context, key string, value any) error

	// Get gets value by key, returns nil if key doesn't exist | 获取键对应的值，键不存在时返回nil
	Get(ctx context.Context, key string) (any, error)

	// GetAndDelete atomically gets the value and deletes the key | 原子获取并删除键
	GetAndDelete(ctx context.Context, key string) (any, error)

	// Delete deletes one or more keys | 删除一个或多个键
	Delete(ctx context.Context, keys ...string) error

	// Exists checks if key exists | 检查键是否存在
	Exists(ctx context.Context, key string) bool

	// ============== Key Management | 键管理 ==============

	// Keys gets all keys matching pattern (e.g., "user:*") | 获取匹配模式的所有键（如："user:*"）
	Keys(ctx context.Context, pattern string) ([]string, error)

	// Expire sets expiration time for key | 设置键的过期时间
	Expire(ctx context.Context, key string, expiration time.Duration) error

	// TTL gets remaining time to live (-1 if no expiration, -2 if key doesn't exist) | 获取键的剩余生存时间（-1表示永不过期，-2表示键不存在）
	TTL(ctx context.Context, key string) (time.Duration, error)

	// ============== Utility Methods | 工具方法 ==============

	// Clear clears all data (use with caution, mainly for testing) | 清空所有数据（谨慎使用，主要用于测试）
	Clear(ctx context.Context) error

	// Ping checks if storage is accessible | 检查存储是否可访问
	Ping(ctx context.Context) error
}
