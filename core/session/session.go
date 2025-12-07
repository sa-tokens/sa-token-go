package session

import (
	"context"
	"errors"
	"fmt"
	"github.com/click33/sa-token-go/core/codec"
	"github.com/click33/sa-token-go/core/log"
	"github.com/click33/sa-token-go/core/serror"
	"sync"
	"time"

	"github.com/click33/sa-token-go/core/adapter"
)

// Session Session object for storing user data | 会话对象，用于存储用户数据
type Session struct {
	ID         string          `json:"id"`         // Session ID | Session标识
	CreateTime int64           `json:"createTime"` // Creation time | 创建时间
	Data       map[string]any  `json:"data"`       // Session data | 数据
	mu         sync.RWMutex    `json:"-"`          // Read-write lock | 读写锁
	storage    adapter.Storage `json:"-"`          // Storage backend | 存储
	prefix     string          `json:"-"`          // Key prefix | 键前缀
	serializer codec.Adapter   // codec Codec adapter for encoding and decoding operations | 编解码操作的编码器适配器
	logger     log.Adapter     // log Log adapter for logging operations | 日志记录操作的适配器
}

// NewSession Creates a new session | 创建新的Session
func NewSession(id string, storage adapter.Storage, prefix string) *Session {
	return &Session{
		ID:         id,
		CreateTime: time.Now().Unix(),
		Data:       make(map[string]any),
		storage:    storage,
		prefix:     prefix,
	}
}

// ============ Data Operations | 数据操作 ============

// Set Sets value | 设置值
func (s *Session) Set(key string, value any, ttl ...time.Duration) error {
	if key == "" {
		return serror.ErrSessionIDEmpty
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.Data[key] = value
	if len(ttl) > 0 && ttl[0] > 0 {
		return s.saveWithTTL(ttl[0])
	}

	return s.save()
}

// SetMulti sets multiple key-value pairs | 设置多个键值对
func (s *Session) SetMulti(values map[string]any, ttl ...time.Duration) error {
	if len(values) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for key, value := range values {
		if key == "" {
			return serror.ErrSessionKeyEmpty
		}
		s.Data[key] = value
	}

	if len(ttl) > 0 && ttl[0] > 0 {
		return s.saveWithTTL(ttl[0])
	}

	return s.save()
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

// Delete 删除键
func (s *Session) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.Data, key)
	return s.save()
}

// Clear Clears all data | 清空所有数据
func (s *Session) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Data = make(map[string]any)
	return s.save()
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
func (s *Session) Renew(ttl time.Duration) error {
	if ttl <= 0 {
		return nil // 不允许设置 0 TTL，避免误删
	}

	key := s.getStorageKey()
	return s.storage.Expire(key, ttl)
}

// ============ Internal Methods | 内部方法 ============

// save Saves session to storage | 保存到存储
func (s *Session) save() error {
	data, err := codec.Encode(s)
	if err != nil {
		return fmt.Errorf("%w: %v", serror.ErrCommonMarshal, err)
	}

	key := s.getStorageKey()
	return s.storage.Set(key, data, 0)
}

// saveWithTTL saves session with TTL | 带 TTL 保存 Session
func (s *Session) saveWithTTL(ttl time.Duration) error {
	data, err := codec.Encode(s)
	if err != nil {
		return fmt.Errorf("%w: %v", serror.ErrCommonMarshal, err)
	}

	key := s.getStorageKey()
	return s.storage.Set(key, string(data), ttl)
}

// getStorageKey Gets storage key for this session | 获取Session的存储键
func (s *Session) getStorageKey() string {
	return s.prefix + SessionKeyPrefix + s.ID
}

// ============ Static Methods | 静态方法 ============

// Load Loads session from storage | 从存储加载
func Load(ctx context.Context, id string, prefix string, storage adapter.Storage, codecAdapter codec.Adapter, logAdapter log.Adapter) (*Session, error) {
	if id == "" {
		return nil, errors.New("session id cannot be empty")
	}

	data, err := storage.Get(prefix + SessionKeyPrefix + id)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, serror.ErrSessionNotFound
	}

	raw, err := codec.UnifyToBytes(data)
	if err != nil {
		return nil, err
	}

	var session Session
	if err = codec.Decode(raw, &session); err != nil {
		return nil, fmt.Errorf("%w: %v", serror.ErrCommonUnmarshal, err)
	}

	session.storage = storage
	session.prefix = prefix
	return &session, nil
}

// Destroy Destroys session | 销毁Session
func (s *Session) Destroy() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := s.getStorageKey()
	return s.storage.Delete(key)
}
