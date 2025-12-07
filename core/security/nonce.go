package security

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/click33/sa-token-go/core/config"
	"sync"
	"time"

	"github.com/click33/sa-token-go/core/adapter"
)

// Nonce Anti-Replay Attack Implementation
// Nonce 防重放攻击实现
//
// Flow | 流程:
// 1. Generate() - Create unique nonce and store with TTL | 生成唯一nonce并存储（带过期时间）
// 2. Verify() - Check existence and delete (one-time use) | 检查存在性并删除（一次性使用）
// 3. Auto-expire after TTL (default 5min) | TTL后自动过期（默认5分钟）
//
// Usage | 用法:
//   nonce, _ := manager.GenerateNonce()
//   valid := manager.VerifyNonce(nonce)  // true
//   valid = manager.VerifyNonce(nonce)   // false (replay prevented)

// Constants for nonce | Nonce常量
const (
	DefaultNonceTTL = 5 * time.Minute // Default nonce expiration | 默认nonce过期时间
	NonceLength     = 32              // Nonce byte length | Nonce字节长度
	NonceKeySuffix  = "nonce:"        // Key suffix after prefix | 前缀后的键后缀
)

// Error variables | 错误变量
var (
	ErrInvalidNonce = fmt.Errorf("invalid or expired nonce")
)

// NonceManager Nonce manager for anti-replay attacks | Nonce管理器，用于防重放攻击
type NonceManager struct {
	storage      adapter.Storage
	globalConfig *config.Config // Global authentication configuration | 全局认证配置
	keyPrefix    string         // Configurable prefix | 可配置的前缀
	ttl          time.Duration
	mu           sync.RWMutex
}

// NewNonceManager Creates a new nonce manager | 创建新的Nonce管理器
// prefix: key prefix (e.g., "satoken:" or "" for Java compatibility) | 键前缀（如："satoken:" 或 "" 兼容Java）
// ttl: time to live, default 5 minutes | 过期时间，默认5分钟
func NewNonceManager(storage adapter.Storage, prefix string, ttl time.Duration) *NonceManager {
	if ttl == 0 {
		ttl = DefaultNonceTTL
	}
	return &NonceManager{
		storage:   storage,
		keyPrefix: prefix,
		ttl:       ttl,
	}
}

// Generate Generates a new nonce and stores it | 生成新的nonce并存储
// Returns 64-char hex string | 返回64字符的十六进制字符串
func (nm *NonceManager) Generate() (string, error) {
	bytes := make([]byte, NonceLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	nonce := hex.EncodeToString(bytes)

	key := nm.getNonceKey(nonce)
	if err := nm.storage.Set(key, time.Now().Unix(), nm.ttl); err != nil {
		return "", fmt.Errorf("failed to store nonce: %w", err)
	}

	return nonce, nil
}

// Verify Verifies nonce and consumes it (one-time use) | 验证nonce并消费它（一次性使用）
// Returns false if nonce doesn't exist or already used | 如果nonce不存在或已使用则返回false
func (nm *NonceManager) Verify(nonce string) bool {
	if nonce == "" {
		return false
	}

	key := nm.getNonceKey(nonce)

	nm.mu.Lock()
	defer nm.mu.Unlock()

	if !nm.storage.Exists(key) {
		return false
	}

	nm.storage.Delete(key)
	return true
}

// VerifyAndConsume Verifies and consumes nonce, returns error if invalid | 验证并消费nonce，无效时返回错误
func (nm *NonceManager) VerifyAndConsume(nonce string) error {
	if !nm.Verify(nonce) {
		return ErrInvalidNonce
	}
	return nil
}

// IsValid Checks if nonce is valid without consuming it | 检查nonce是否有效（不消费）
func (nm *NonceManager) IsValid(nonce string) bool {
	if nonce == "" {
		return false
	}

	key := nm.getNonceKey(nonce)

	nm.mu.RLock()
	defer nm.mu.RUnlock()

	return nm.storage.Exists(key)
}

// getNonceKey Gets storage key for nonce | 获取nonce的存储键
func (nm *NonceManager) getNonceKey(nonce string) string {
	return nm.keyPrefix + NonceKeySuffix + nonce
}
