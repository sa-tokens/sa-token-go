// @Author daixk 2025/11/21 9:57:00
package codec

import (
	"sync"
	"sync/atomic"
)

// Built-in serializer names | 内置序列化器名称
const (
	SerializerJSON    = "json"
	SerializerMsgPack = "msgpack"
)

// 默认初始化全局的codec实现 这里先注释 向后兼容

// serializerHolder wraps Adapter to ensure atomic.Value type consistency | 包装 Adapter 以确保 atomic.Value 类型一致性
type serializerHolder struct {
	s Adapter
}

// serializerValue stores the global serializer using atomic.Value | 使用 atomic.Value 存储全局序列化器
var (
	serializerValue atomic.Value // stores serializerHolder | 存储 serializerHolder
	serializerMu    sync.Mutex   // used only for SetDefaultSerializer write lock | 仅用于写入加锁
)

func init() {
	// Initialize default JSON serializer | 初始化默认 JSON 序列化器
	serializerValue.Store(serializerHolder{s: &JSONSerializer{}})
}

// SetDefaultSerializer sets the global serializer | 设置全局默认序列化器
func SetDefaultSerializer(s Adapter) {
	if s == nil {
		return
	}

	// lock ensures write ordering | 加锁确保写入顺序一致
	serializerMu.Lock()
	serializerValue.Store(serializerHolder{s: s})
	serializerMu.Unlock()
}

// GetDefaultSerializer returns the global serializer | 获取全局默认序列化器
func GetDefaultSerializer() Adapter {
	return serializerValue.Load().(serializerHolder).s
}

// Encode encodes a value using the global serializer | 使用全局序列化器编码数据
func Encode(v any) ([]byte, error) {
	return GetDefaultSerializer().Encode(v)
}

// Decode decodes bytes using the global serializer | 使用全局序列化器解码数据到目标对象
func Decode(data []byte, v any) error {
	return GetDefaultSerializer().Decode(data, v)
}

// NewSerializer creates a serializer by name | 根据名称创建对应的序列化器
func NewSerializer(name string) Adapter {
	switch name {
	case SerializerJSON, "":
		return &JSONSerializer{}
	case SerializerMsgPack:
		return &MsgPackSerializer{}
	default:
		return &JSONSerializer{}
	}
}

// NewSerializerMust returns serializer or panic if not found | 根据名称创建序列化器，未找到则 panic
func NewSerializerMust(name string) Adapter {
	switch name {
	case SerializerJSON, "":
		return &JSONSerializer{}
	case SerializerMsgPack:
		return &MsgPackSerializer{}
	}
	panic("unknown serializer: " + name)
}

// NewSerializerMustWithJson returns JSON serializer if name not found | 根据名称创建序列化器，未找到则返回 JSON 序列化器
func NewSerializerMustWithJson(name string) Adapter {
	return NewSerializer(name)
}
