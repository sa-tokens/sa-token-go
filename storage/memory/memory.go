package memory

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/click33/sa-token-go/core/adapter"
)

var (
	// ErrKeyNotFound 键不存在错误
	ErrKeyNotFound = errors.New("key not found")
	// ErrKeyExpired 键已过期错误
	ErrKeyExpired = errors.New("key expired")
)

// item 存储项
type item struct {
	value      any
	expiration int64 // 过期时间戳（0表示永不过期）
}

// isExpired 检查是否过期（使用传入的时间戳避免重复调用）
func (i *item) isExpired(now int64) bool {
	return i.expiration > 0 && now > i.expiration
}

// Storage 内存存储实现
type Storage struct {
	data       map[string]*item
	mu         sync.RWMutex
	cancelFunc context.CancelFunc // 用于停止清理协程
	closed     bool
}

// NewStorage 创建内存存储
func NewStorage() adapter.Storage {
	return NewStorageWithCleanupInterval(time.Minute)
}

// NewStorageWithCleanupInterval 创建内存存储
func NewStorageWithCleanupInterval(interval time.Duration) adapter.Storage {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Storage{
		data:       make(map[string]*item),
		cancelFunc: cancel,
	}
	// 启动清理协程
	go s.cleanup(ctx, interval)
	return s
}

// Set 设置键值对
func (s *Storage) Set(key string, value any, expiration time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var exp int64
	if expiration > 0 {
		exp = time.Now().Add(expiration).Unix()
	}

	s.data[key] = &item{
		value:      value,
		expiration: exp,
	}

	return nil
}

// SetKeepTTL Sets value without modifying TTL | 设置键值但保持原有TTL不变
func (s *Storage) SetKeepTTL(key string, value any) error {
	now := time.Now().Unix()

	s.mu.Lock()
	defer s.mu.Unlock()

	item, exists := s.data[key]
	if !exists {
		// 键不存在，返回错误（与Redis保持一致）
		return ErrKeyNotFound
	}

	// If expired, treat as not found | 如果已经过期，则视为不存在
	if item.isExpired(now) {
		delete(s.data, key)
		return ErrKeyExpired
	}

	// Replace value only, keep original expiration | 仅更新value，保持expiration不变
	item.value = value

	return nil
}

// Get 获取值
func (s *Storage) Get(key string) (any, error) {
	now := time.Now().Unix()

	s.mu.RLock()
	item, exists := s.data[key]
	s.mu.RUnlock()

	if !exists {
		return nil, ErrKeyNotFound
	}

	if item.isExpired(now) {
		// 异步删除过期项
		go s.Delete(key)
		return nil, ErrKeyExpired
	}

	return item.value, nil
}

// GetAndDelete atomically gets the value and deletes the key | 原子获取并删除键
func (s *Storage) GetAndDelete(key string) (any, error) {
	now := time.Now().Unix()

	s.mu.Lock()
	defer s.mu.Unlock()

	item, exists := s.data[key]
	if !exists {
		return nil, ErrKeyNotFound
	}

	if item.isExpired(now) {
		delete(s.data, key)
		return nil, ErrKeyExpired
	}

	val := item.value
	delete(s.data, key)

	return val, nil
}

// Delete 删除键
func (s *Storage) Delete(keys ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, key := range keys {
		delete(s.data, key)
	}
	return nil
}

// Exists 检查键是否存在
func (s *Storage) Exists(key string) bool {
	now := time.Now().Unix()

	s.mu.RLock()
	item, exists := s.data[key]
	s.mu.RUnlock()

	if !exists {
		return false
	}

	if item.isExpired(now) {
		// 异步删除过期项
		go s.Delete(key)
		return false
	}

	return true
}

// Keys 获取匹配模式的所有键
func (s *Storage) Keys(pattern string) ([]string, error) {
	now := time.Now().Unix()

	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := make([]string, 0, 16) // 预分配容量
	for key, item := range s.data {
		if item.isExpired(now) {
			continue
		}
		if matchPattern(key, pattern) {
			keys = append(keys, key)
		}
	}

	return keys, nil
}

// Expire 设置键的过期时间
func (s *Storage) Expire(key string, expiration time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	item, exists := s.data[key]
	if !exists {
		return ErrKeyNotFound
	}

	// expiration>0 设置 TTL
	if expiration > 0 {
		item.expiration = time.Now().Add(expiration).Unix()
		return nil
	}

	// 兼容redis的过期时间设置
	delete(s.data, key)
	return nil
}

// TTL 获取键的剩余生存时间
func (s *Storage) TTL(key string) (time.Duration, error) {
	now := time.Now().Unix()

	s.mu.RLock()
	item, exists := s.data[key]
	s.mu.RUnlock()

	if !exists {
		return -2 * time.Second, ErrKeyNotFound
	}

	if item.expiration == 0 {
		return -1 * time.Second, nil // 永不过期
	}

	ttl := item.expiration - now
	if ttl < 0 {
		return -2 * time.Second, nil // 已过期
	}

	return time.Duration(ttl) * time.Second, nil
}

// Clear 清空所有数据
func (s *Storage) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data = make(map[string]*item)
	return nil
}

// Ping 检查存储可用性
func (s *Storage) Ping() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return errors.New("storage is closed")
	}
	return nil
}

// Close 关闭存储，停止清理协程
func (s *Storage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true
	if s.cancelFunc != nil {
		s.cancelFunc()
	}
	return nil
}

// cleanup 定期清理过期数据
func (s *Storage) cleanup(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.removeExpiredItems()
		}
	}
}

// removeExpiredItems 批量删除过期项
func (s *Storage) removeExpiredItems() {
	now := time.Now().Unix()

	s.mu.Lock()
	defer s.mu.Unlock()

	// 批量收集过期键
	expiredKeys := make([]string, 0, 8)
	for key, item := range s.data {
		if item.isExpired(now) {
			expiredKeys = append(expiredKeys, key)
		}
	}

	// 批量删除
	for _, key := range expiredKeys {
		delete(s.data, key)
	}
}

// matchPattern 简单的模式匹配
func matchPattern(key, pattern string) bool {
	// 空模式或通配符匹配所有
	if pattern == "" || pattern == "*" {
		return true
	}

	// 移除前缀 **/（支持 Redis 风格）
	pattern = strings.TrimPrefix(pattern, "**/")

	// 没有通配符，精确匹配
	if !strings.Contains(pattern, "*") {
		return key == pattern
	}

	// 前缀匹配：prefix*
	if strings.HasSuffix(pattern, "*") && strings.Count(pattern, "*") == 1 {
		return strings.HasPrefix(key, pattern[:len(pattern)-1])
	}

	// 后缀匹配：*suffix
	if strings.HasPrefix(pattern, "*") && strings.Count(pattern, "*") == 1 {
		return strings.HasSuffix(key, pattern[1:])
	}

	// 包含匹配：prefix*suffix
	if strings.Count(pattern, "*") == 1 {
		parts := strings.SplitN(pattern, "*", 2)
		return strings.HasPrefix(key, parts[0]) && strings.HasSuffix(key, parts[1])
	}

	// 复杂模式：递归匹配
	return simpleWildcardMatch(key, pattern)
}

// simpleWildcardMatch 简单通配符匹配
func simpleWildcardMatch(s, pattern string) bool {
	if pattern == "" {
		return s == ""
	}
	if pattern == "*" {
		return true
	}

	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return s == pattern
	}

	// 检查第一部分
	if parts[0] != "" && !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]

	// 检查最后一部分
	if parts[len(parts)-1] != "" {
		if !strings.HasSuffix(s, parts[len(parts)-1]) {
			return false
		}
		s = s[:len(s)-len(parts[len(parts)-1])]
	}

	// 检查中间部分
	for i := 1; i < len(parts)-1; i++ {
		if parts[i] == "" {
			continue
		}
		idx := strings.Index(s, parts[i])
		if idx == -1 {
			return false
		}
		s = s[idx+len(parts[i]):]
	}

	return true
}
