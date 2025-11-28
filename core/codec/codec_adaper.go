// @Author daixk 2025/11/27 20:55:00
package codec

type Adapter interface {
	Encode(v any) ([]byte, error)    // Encode to bytes | 编码
	Decode(data []byte, v any) error // Decode to struct | 解码
	Name() string                    // Serializer name | 序列化器名称
}
