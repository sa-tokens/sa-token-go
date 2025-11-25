// @Author daixk 2025/11/24 22:05:00
package codec

import "sync"

// DefaultSerializer is the global serializer (JSON recommended) | 全局默认序列化器（推荐使用 JSON）
var (
	DefaultSerializer Serializer = &JSONSerializer{}
	serializerMu      sync.RWMutex
)

// SetDefaultSerializer sets the global serializer | 设置全局默认序列化器
func SetDefaultSerializer(s Serializer) {
	if s == nil {
		return
	}
	serializerMu.Lock()
	DefaultSerializer = s
	serializerMu.Unlock()
}

// GetDefaultSerializer gets the global serializer | 获取全局默认序列化器
func GetDefaultSerializer() Serializer {
	serializerMu.RLock()
	s := DefaultSerializer
	serializerMu.RUnlock()
	return s
}
