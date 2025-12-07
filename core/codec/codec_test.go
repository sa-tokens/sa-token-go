// @Author daixk 2025/12/6 17:04:00
package codec

import (
	"github.com/click33/sa-token-go/core/serror"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// -------------------- Mock Struct --------------------

type mockStruct struct {
	Name string
	Age  int
}

// -------------------- JSONSerializer Tests --------------------

// TestJSONSerializerEncodeDecode tests JSON encode/decode behavior | 测试 JSON 序列化器的编码与解码行为
func TestJSONSerializerEncodeDecode(t *testing.T) {
	s := &JSONSerializer{}
	input := mockStruct{Name: "Alice", Age: 20}

	// Encode
	data, err := s.Encode(input)
	if err != nil {
		t.Fatalf("JSON Encode failed: %v", err)
	}
	if !strings.Contains(string(data), "Alice") {
		t.Errorf("JSON Encode output missing field: got %s", string(data))
	}

	// Decode
	var output mockStruct
	err = s.Decode(data, &output)
	if err != nil {
		t.Fatalf("JSON Decode failed: %v", err)
	}
	if !reflect.DeepEqual(input, output) {
		t.Errorf("JSON Decode mismatch: got %+v, want %+v", output, input)
	}

	// Name check
	if s.Name() != SerializerJSON {
		t.Errorf("JSONSerializer.Name() = %s, want %s", s.Name(), SerializerJSON)
	}
}

// -------------------- MsgPackSerializer Tests --------------------

// TestMsgPackSerializerEncodeDecode tests MsgPack encode/decode | 测试 MsgPack 序列化器的编码与解码行为
func TestMsgPackSerializerEncodeDecode(t *testing.T) {
	s := &MsgPackSerializer{}
	input := mockStruct{Name: "Bob", Age: 25}

	data, err := s.Encode(input)
	if err != nil {
		t.Fatalf("MsgPack Encode failed: %v", err)
	}

	var output mockStruct
	err = s.Decode(data, &output)
	if err != nil {
		t.Fatalf("MsgPack Decode failed: %v", err)
	}
	if !reflect.DeepEqual(input, output) {
		t.Errorf("MsgPack Decode mismatch: got %+v, want %+v", output, input)
	}

	if s.Name() != SerializerMsgPack {
		t.Errorf("MsgPackSerializer.Name() = %s, want %s", s.Name(), SerializerMsgPack)
	}
}

// -------------------- Global Serializer Tests --------------------

// TestGlobalSerializerDefault tests default global serializer | 测试默认全局序列化器（应为 JSON）
func TestGlobalSerializerDefault(t *testing.T) {
	def := GetDefaultSerializer()
	if def == nil {
		t.Fatal("default serializer should not be nil")
	}
	if def.Name() != SerializerJSON {
		t.Errorf("default serializer name = %s, want %s", def.Name(), SerializerJSON)
	}
}

// TestSetDefaultSerializer tests setting and getting the global serializer | 测试设置与获取全局序列化器
func TestSetDefaultSerializer(t *testing.T) {
	SetDefaultSerializer(&MsgPackSerializer{})
	s := GetDefaultSerializer()
	if s.Name() != SerializerMsgPack {
		t.Errorf("expected global serializer to be msgpack, got %s", s.Name())
	}

	SetDefaultSerializer(&JSONSerializer{})
	s = GetDefaultSerializer()
	if s.Name() != SerializerJSON {
		t.Errorf("expected global serializer to be json, got %s", s.Name())
	}

	// nil should not change current serializer
	current := GetDefaultSerializer()
	SetDefaultSerializer(nil)
	if GetDefaultSerializer() != current {
		t.Error("SetDefaultSerializer(nil) should not change the serializer")
	}
}

// TestConcurrentSetDefaultSerializer tests concurrent SetDefaultSerializer safety | 测试并发安全性
func TestConcurrentSetDefaultSerializer(t *testing.T) {
	wg := sync.WaitGroup{}
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				SetDefaultSerializer(&JSONSerializer{})
			} else {
				SetDefaultSerializer(&MsgPackSerializer{})
			}
		}(i)
	}
	wg.Wait()
	_ = GetDefaultSerializer() // ensure no panic
}

// -------------------- Encode / Decode Entry Tests --------------------

// TestEncodeDecodeGlobal tests Encode/Decode helpers using global serializer | 测试全局编码解码辅助函数
func TestEncodeDecodeGlobal(t *testing.T) {
	SetDefaultSerializer(&JSONSerializer{})

	src := mockStruct{Name: "Eve", Age: 30}
	data, err := Encode(src)
	if err != nil {
		t.Fatalf("Encode() failed: %v", err)
	}

	var dst mockStruct
	err = Decode(data, &dst)
	if err != nil {
		t.Fatalf("Decode() failed: %v", err)
	}

	if !reflect.DeepEqual(src, dst) {
		t.Errorf("Decode() result mismatch: got %+v, want %+v", dst, src)
	}
}

// -------------------- NewSerializer Tests --------------------

// TestNewSerializer tests serializer creation by name | 测试根据名称创建序列化器
func TestNewSerializer(t *testing.T) {
	s := NewSerializer("json")
	if s.Name() != SerializerJSON {
		t.Errorf("NewSerializer(json) got %s", s.Name())
	}

	s = NewSerializer("msgpack")
	if s.Name() != SerializerMsgPack {
		t.Errorf("NewSerializer(msgpack) got %s", s.Name())
	}

	s = NewSerializer("unknown")
	if s.Name() != SerializerJSON {
		t.Errorf("NewSerializer(unknown) default fallback should be json, got %s", s.Name())
	}
}

// TestNewSerializerMust tests NewSerializerMust panic on invalid name | 测试 NewSerializerMust 异常情况
func TestNewSerializerMust(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for unknown serializer, got none")
		}
	}()
	_ = NewSerializerMust("invalid-name")
}

// TestNewSerializerMustWithJson ensures fallback to JSON | 测试 NewSerializerMustWithJson 返回 JSON
func TestNewSerializerMustWithJson(t *testing.T) {
	s := NewSerializerMustWithJson("non-exist")
	if s.Name() != SerializerJSON {
		t.Errorf("expected fallback JSON, got %s", s.Name())
	}
}

// -------------------- UnifyToBytes Tests --------------------

// TestUnifyToBytes tests type conversion to []byte | 测试数据统一转换为 []byte
func TestUnifyToBytes(t *testing.T) {
	data, err := UnifyToBytes([]byte("abc"))
	if err != nil || string(data) != "abc" {
		t.Errorf("UnifyToBytes([]byte) failed: %v", err)
	}

	data, err = UnifyToBytes("xyz")
	if err != nil || string(data) != "xyz" {
		t.Errorf("UnifyToBytes(string) failed: %v", err)
	}

	_, err = UnifyToBytes(123)
	if err == nil {
		t.Error("UnifyToBytes(int) should return error")
	}

	_, err = UnifyToBytes(nil)
	if err == nil || err != serror.ErrInvalidTokenData {
		t.Error("UnifyToBytes(nil) should return ErrInvalidTokenData")
	}
}

// -------------------- Benchmark --------------------

// BenchmarkEncodeJSON benchmarks JSON encoding performance | 基准测试 JSON 编码性能
func BenchmarkEncodeJSON(b *testing.B) {
	s := &JSONSerializer{}
	data := mockStruct{Name: "Benchmark", Age: 100}
	for i := 0; i < b.N; i++ {
		_, _ = s.Encode(data)
	}
}

// BenchmarkDecodeJSON benchmarks JSON decoding performance | 基准测试 JSON 解码性能
func BenchmarkDecodeJSON(b *testing.B) {
	s := &JSONSerializer{}
	raw, _ := s.Encode(mockStruct{Name: "Benchmark", Age: 100})
	var v mockStruct
	for i := 0; i < b.N; i++ {
		_ = s.Decode(raw, &v)
	}
}

// BenchmarkEncodeMsgPack benchmarks MsgPack encoding performance | 基准测试 MsgPack 编码性能
func BenchmarkEncodeMsgPack(b *testing.B) {
	s := &MsgPackSerializer{}
	data := mockStruct{Name: "Benchmark", Age: 100}
	for i := 0; i < b.N; i++ {
		_, _ = s.Encode(data)
	}
}

// BenchmarkDecodeMsgPack benchmarks MsgPack decoding performance | 基准测试 MsgPack 解码性能
func BenchmarkDecodeMsgPack(b *testing.B) {
	s := &MsgPackSerializer{}
	raw, _ := s.Encode(mockStruct{Name: "Benchmark", Age: 100})
	var v mockStruct
	for i := 0; i < b.N; i++ {
		_ = s.Decode(raw, &v)
	}
}
