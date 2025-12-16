// @Author daixk 2025/12/11 22:20:00
package security

import "time"

// Constants for nonce | Nonce常量
const (
	DefaultNonceTTL = 5 * time.Minute // Default nonce expiration | 默认nonce过期时间
	NonceLength     = 32              // Nonce byte length | Nonce字节长度
	NonceKeySuffix  = "nonce:"        // Key suffix after prefix | 前缀后的键后缀
)

// Constants for refresh token | 刷新令牌常量
const (
	DefaultRefreshTTL  = 30 * 24 * time.Hour // 30 days | 30天
	DefaultAccessTTL   = 2 * time.Hour       // 2 hours | 2小时
	RefreshTokenLength = 32                  // Refresh token byte length | 刷新令牌字节长度
	RefreshKeySuffix   = "refresh:"          // Key suffix after prefix | 前缀后的键后缀
)
