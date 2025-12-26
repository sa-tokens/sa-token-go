package security

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/click33/sa-token-go/core"
	"github.com/click33/sa-token-go/core/adapter"
	"github.com/click33/sa-token-go/storage/memory"
	"sync"
	"time"
)

// Nonce Anti-Replay Attack Implementation | Nonce 防重放攻击实现
//
// Flow | 流程:
// 1. Generate() - Create unique nonce and store with TTL | 生成唯一nonce并存储（带过期时间）
// 2. Verify() - Check existence and delete (one-time use) | 检查存在性并删除（一次性使用）
// 3. Auto-expire after TTL (log 5min) | TTL后自动过期（默认5分钟）
//
// Usage | 用法:
//   nonce, _ := manager.Generate()
//   valid := manager.Verify(nonce)  // true
//   valid = manager.Verify(nonce)   // false (replay prevented)

// NonceManager Nonce manager for anti-replay attacks | Nonce管理器，用于防重放攻击
type NonceManager struct {
	authType  string          // Authentication system type | 认证体系类型
	keyPrefix string          // Configurable prefix | 可配置的前缀
	ttl       time.Duration   // Nonce TTL | Nonce有效期
	mu        sync.RWMutex    // RWMutex for concurrent access | 并发访问读写锁
	storage   adapter.Storage // Storage adapter (Redis, Memory, etc.) | 存储适配器（如 Redis、Memory）
}

// NewNonceManager Creates a new nonce manager | 创建新的Nonce管理器
func NewNonceManager(authType, prefix string, storage adapter.Storage, ttl time.Duration) *NonceManager {
	if ttl == 0 {
		ttl = DefaultNonceTTL // Default TTL 5 minutes | 默认5分钟
	}
	if storage == nil {
		storage = memory.NewStorage() // Use in-memory storage if not provided | 如果未提供使用内存存储
	}

	return &NonceManager{
		authType:  authType,
		keyPrefix: prefix,
		storage:   storage,
		ttl:       ttl,
	}
}

// Generate Generates a new nonce and stores it | 生成新的nonce并存储
func (nm *NonceManager) Generate(ctx context.Context) (string, error) {
	// Create byte slice for nonce | 创建字节切片生成nonce
	bytes := make([]byte, NonceLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	// Encode bytes to hex string | 编码为16进制字符串
	nonce := hex.EncodeToString(bytes)

	// Build storage key | 构建存储键
	key := nm.getNonceKey(nonce)
	if err := nm.storage.Set(ctx, key, time.Now().Unix(), nm.ttl); err != nil {
		return "", fmt.Errorf("%w: %v", core.ErrStorageUnavailable, err)
	}

	return nonce, nil
}

// Verify Verifies nonce and consumes it (one-time use) Returns false if nonce doesn't exist or already used | 验证nonce并消费它（一次性使用）如果nonce不存在或已使用则返回false
func (nm *NonceManager) Verify(ctx context.Context, nonce string) bool {
	if nonce == "" {
		return false
	}

	// Build storage key | 构建存储键
	key := nm.getNonceKey(nonce)

	nm.mu.Lock()         // Acquire write lock | 获取写锁
	defer nm.mu.Unlock() // Release lock after function | 函数结束释放锁

	// Nonce not found | 未找到nonce
	if !nm.storage.Exists(ctx, key) {
		return false
	}

	// Consume nonce | 消耗nonce
	_ = nm.storage.Delete(ctx, key)

	return true
}

// VerifyAndConsume Verifies and consumes nonce, returns error if invalid | 验证并消费nonce，无效时返回错误
func (nm *NonceManager) VerifyAndConsume(ctx context.Context, nonce string) error {
	if !nm.Verify(ctx, nonce) {
		return core.ErrInvalidNonce
	}
	return nil
}

// IsValid Checks if nonce is valid without consuming it | 检查nonce是否有效（不消费）
func (nm *NonceManager) IsValid(ctx context.Context, nonce string) bool {
	if nonce == "" {
		return false
	}

	// Build storage key | 构建存储键
	key := nm.getNonceKey(nonce)

	nm.mu.RLock()         // Acquire read lock | 获取读锁
	defer nm.mu.RUnlock() // Release read lock | 释放读锁

	// Return existence | 返回是否存在
	return nm.storage.Exists(ctx, key)
}

// getNonceKey Gets storage key for nonce | 获取nonce的存储键
func (nm *NonceManager) getNonceKey(nonce string) string {
	return nm.keyPrefix + nm.authType + NonceKeySuffix + nonce
}
