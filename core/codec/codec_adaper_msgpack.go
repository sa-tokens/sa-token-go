// @Author daixk 2025/11/27 20:58:00
package codec

import "github.com/vmihailenco/msgpack/v5"

type MsgPackSerializer struct{}

func (s *MsgPackSerializer) Encode(v any) ([]byte, error) {
	return msgpack.Marshal(v)
}

func (s *MsgPackSerializer) Decode(data []byte, v any) error {
	return msgpack.Unmarshal(data, v)
}

func (s *MsgPackSerializer) Name() string { return SerializerMsgPack }
