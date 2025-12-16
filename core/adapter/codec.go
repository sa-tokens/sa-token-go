// @Author daixk 2025/12/12 10:46:00
package adapter

// Codec defines serialization behavior abstraction | 序列化行为抽象接口
type Codec interface {
	Encode(v any) ([]byte, error)    // Encode value to byte slice | 将对象编码为字节数组
	Decode(data []byte, v any) error // Decode byte slice to target value | 将字节数组解码到目标对象
	Name() string                    // Return codec implementation name | 返回序列化器名称
}
