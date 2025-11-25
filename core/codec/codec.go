// @Author daixk 2025/11/21 9:57:00
package codec

import (
	"encoding/json"
	"github.com/click33/sa-token-go/core/serror"
	"github.com/vmihailenco/msgpack/v5"
)

// Serializer defines interface for encoding/decoding TokenInfo | TokenInfo 编解码接口
type Serializer interface {
	Marshal(v any) ([]byte, error)      // Encode to bytes | 编码
	Unmarshal(data []byte, v any) error // Decode to struct | 解码
	Name() string                       // Serializer name | 序列化器名称（例如 json/msgpack）
}

// Built-in serializer names | 内置序列化器名称
const (
	SerializerJSON    = "json"
	SerializerMsgPack = "msgpack"
)

// -------------------- JSON Serializer --------------------

type JSONSerializer struct{}

func (s *JSONSerializer) Marshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (s *JSONSerializer) Unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func (s *JSONSerializer) Name() string { return SerializerJSON }

// -------------------- MsgPack Serializer --------------------

type MsgPackSerializer struct{}

func (s *MsgPackSerializer) Marshal(v any) ([]byte, error) {
	return msgpack.Marshal(v)
}

func (s *MsgPackSerializer) Unmarshal(data []byte, v any) error {
	return msgpack.Unmarshal(data, v)
}

func (s *MsgPackSerializer) Name() string { return SerializerMsgPack }

// UnifyToBytes converts storage return (string or []byte) into []byte safely.
func UnifyToBytes(data any) ([]byte, error) {
	if data == nil {
		return nil, serror.ErrInvalidTokenData
	}

	switch v := data.(type) {
	case []byte:
		return v, nil
	case string:
		return []byte(v), nil
	default:
		return nil, serror.ErrInvalidTokenData
	}
}

// NewSerializer 根据名称创建对应的序列化器
func NewSerializer(name string) Serializer {
	switch name {
	case SerializerJSON, "":
		return &JSONSerializer{}
	case SerializerMsgPack:
		return &MsgPackSerializer{}
	default:
		return &JSONSerializer{}
	}
}

// NewSerializerMust 根据名称创建对应的序列化器,出现错误直接panic
func NewSerializerMust(name string) Serializer {
	return NewSerializer(name)
}
