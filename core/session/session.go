package session

import (
	"context"
	"fmt"
	codec_json "github.com/click33/sa-token-go/codec/json"
	"github.com/click33/sa-token-go/core"
	"github.com/click33/sa-token-go/storage/memory"
	"sync"
	"time"

	"github.com/click33/sa-token-go/core/adapter"
)

// Session Session object for storing user data | 会话对象，用于存储用户数据
type Session struct {
	AuthType   string         `json:"authType"`   // Authentication system type | 认证体系类型
	ID         string         `json:"id"`         // Session ID | Session标识
	CreateTime int64          `json:"createTime"` // Creation time | 创建时间
	Data       map[string]any `json:"data"`       // Session data | 数据

	prefix     string          `json:"-" msgpack:"-"` // Key prefix | 键前缀
	mu         sync.RWMutex    `json:"-" msgpack:"-"` // Read-write lock | 读写锁
	storage    adapter.Storage `json:"-" msgpack:"-"` // Storage adapter (Redis, Memory, etc.) | 存储适配器（如 Redis、Memory）
	serializer adapter.Codec   `json:"-" msgpack:"-"` // Codec adapter for encoding and decoding operations | 编解码器适配器
}

// NewSession Creates a new session | 创建新的Session
func NewSession(authType, prefix, id string, storage adapter.Storage, serializer adapter.Codec) *Session {
	if storage == nil {
		storage = memory.NewStorage()
	}
	if serializer == nil {
		serializer = codec_json.NewJSONSerializer()
	}

	return &Session{
		AuthType:   authType,
		ID:         id,
		CreateTime: time.Now().Unix(),
		Data:       make(map[string]any),
		prefix:     prefix,
		storage:    storage,
		serializer: serializer,
	}
}

// SetDependencies sets internal dependencies for a decoded session | 设置反序列化后的 Session 的内部依赖
func (s *Session) SetDependencies(prefix string, storage adapter.Storage, serializer adapter.Codec) {
	if storage == nil {
		storage = memory.NewStorage()
	}
	if serializer == nil {
		serializer = codec_json.NewJSONSerializer()
	}
	s.prefix = prefix
	s.storage = storage
	s.serializer = serializer
}

// ============ Data Operations | 数据操作 ============

// Set Sets value | 设置值
func (s *Session) Set(ctx context.Context, key string, value any, ttl ...time.Duration) error {
	if key == "" {
		return core.ErrSessionInvalidDataKey
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.Data[key] = value

	return s.save(ctx, ttl...)
}

// SetMulti sets multiple key-value pairs | 设置多个键值对
func (s *Session) SetMulti(ctx context.Context, valueMap map[string]any, ttl ...time.Duration) error {
	if len(valueMap) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for key, value := range valueMap {
		if key == "" {
			return core.ErrSessionInvalidDataKey
		}
		s.Data[key] = value
	}

	return s.save(ctx, ttl...)
}

// Get Gets value | 获取值
func (s *Session) Get(key string) (any, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	value, exists := s.Data[key]
	return value, exists
}

// GetString gets string value | 获取字符串值
func (s *Session) GetString(key string) string {
	if value, exists := s.Get(key); exists {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}

// GetInt gets integer value | 获取整数值
func (s *Session) GetInt(key string) int {
	if value, exists := s.Get(key); exists {
		switch v := value.(type) {
		case int:
			return v
		case int64:
			return int(v)
		case float64:
			return int(v)
		}
	}
	return 0
}

// GetInt64 获取int64值
func (s *Session) GetInt64(key string) int64 {
	if value, exists := s.Get(key); exists {
		switch v := value.(type) {
		case int64:
			return v
		case int:
			return int64(v)
		case float64:
			return int64(v)
		}
	}
	return 0
}

// GetBool 获取布尔值
func (s *Session) GetBool(key string) bool {
	if value, exists := s.Get(key); exists {
		if b, ok := value.(bool); ok {
			return b
		}
	}
	return false
}

// Has 检查键是否存在
func (s *Session) Has(key string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, exists := s.Data[key]
	return exists
}

// Delete removes a key and preserves TTL | 删除键并保留 TTL
func (s *Session) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.Data, key)
	return s.saveKeepTTL(ctx)
}

// Clear removes all keys but preserves TTL | 清空所有键并保留 TTL
func (s *Session) Clear(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Data = make(map[string]any)
	return s.saveKeepTTL(ctx)
}

// Keys Gets all keys | 获取所有键
func (s *Session) Keys() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys := make([]string, 0, len(s.Data))
	for key := range s.Data {
		keys = append(keys, key)
	}
	return keys
}

// Size Gets data count | 获取数据数量
func (s *Session) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.Data)
}

// IsEmpty Checks if session has no data | 检查Session是否为空
func (s *Session) IsEmpty() bool {
	return s.Size() == 0
}

// Renew extends the session TTL without modifying content | 续期 Session 的 TTL，但不修改内容
func (s *Session) Renew(ctx context.Context, ttl time.Duration) error {
	if ttl < 0 {
		return nil // Skip renewal if ttl is invalid | 跳过无效续期
	}

	key := s.getStorageKey()
	return s.storage.Expire(ctx, key, ttl)
}

// Destroy Destroys session | 销毁Session
func (s *Session) Destroy(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := s.getStorageKey()
	return s.storage.Delete(ctx, key)
}

// ============ Internal Methods | 内部方法 ============

// getStorageKey Gets storage key for this session | 获取Session的存储键
func (s *Session) getStorageKey() string {
	return s.prefix + s.AuthType + SessionKeyPrefix + s.ID
}

// save Saves session to storage | 保存到存储
func (s *Session) save(ctx context.Context, ttl ...time.Duration) error {
	data, err := s.serializer.Encode(s)
	if err != nil {
		return fmt.Errorf("%w: %v", core.ErrSerializeFailed, err)
	}

	key := s.getStorageKey()

	// Default to 0 (no expiration) | 默认使用 0（无过期时间）
	if len(ttl) == 0 || ttl[0] <= 0 {
		err = s.storage.Set(ctx, key, data, 0)
		if err != nil {
			return fmt.Errorf("%w: %v", core.ErrStorageUnavailable, err)
		}
		return nil
	}

	// Save with provided TTL | 使用指定 TTL 保存
	err = s.storage.Set(ctx, key, data, ttl[0])
	if err != nil {
		return fmt.Errorf("%w: %v", core.ErrStorageUnavailable, err)
	}

	return nil
}

// saveKeepTTL saves session while preserving its TTL | 保存 Session 并保留现有 TTL
func (s *Session) saveKeepTTL(ctx context.Context) error {
	data, err := s.serializer.Encode(s)
	if err != nil {
		return fmt.Errorf("%w: %v", core.ErrSerializeFailed, err)
	}

	key := s.getStorageKey()

	// Try to get current TTL | 获取当前 TTL
	// -1: never expires | 永不过期
	// -2: key not found | key不存在
	// >0: remaining TTL | 剩余时间
	ttl, _ := s.storage.TTL(ctx, key)

	// ttl <= 0 means: not found(-2), never expires(-1), or expired
	// All these cases should save with no expiration | 这些情况都保存为永久
	if ttl <= 0 {
		ttl = 0
	}
	// ttl > 0: use original TTL | 使用原有TTL

	err = s.storage.Set(ctx, key, data, ttl)
	if err != nil {
		return fmt.Errorf("%w: %v", core.ErrStorageUnavailable, err)
	}

	return nil
}
