// @Author daixk 2025/12/22 16:08:00
package sgenerator

// Constants for token generation | Token生成常量
const (
	DefaultTimeout      = 2592000          // 30 days (seconds) | 30天（秒）
	DefaultJWTSecret    = "log-secret-key" // Should be overridden in production | 生产环境应覆盖
	TikTokenLength      = 11               // TikTok-style short ID length | Tik风格短ID长度
	TikCharset          = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	HashRandomBytesLen  = 16 // Random bytes length for hash token | 哈希Token的随机字节长度
	TimestampRandomLen  = 8  // Random bytes length for timestamp token | 时间戳Token的随机字节长度
	DefaultSimpleLength = 16 // Default simple token length | 默认简单Token长度
)
