// @Author daixk 2025/11/27 20:57:00
package codec

import "encoding/json"

type JSONSerializer struct{}

func (s *JSONSerializer) Encode(v any) ([]byte, error) {
	return json.Marshal(v)
}

func (s *JSONSerializer) Decode(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func (s *JSONSerializer) Name() string { return SerializerJSON }
