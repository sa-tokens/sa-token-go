// @Author daixk 2025/12/7 19:53:00
package dep

import (
	"errors"
	"github.com/click33/sa-token-go/core/codec"
	"github.com/click33/sa-token-go/core/log"
)

// Dep Dependency manager containing serializer and logger | 依赖管理器，包含序列化和日志记录器
type Dep struct {
	serializer codec.Adapter // Codec adapter for encoding and decoding operations | 编解码器适配器
	logger     log.Adapter   // Log adapter for logging operations | 日志适配器
}

// NewDep Creates a new Dep instance | 创建一个新的 Dep 实例
func NewDep(serializer codec.Adapter, logger log.Adapter) (*Dep, error) {
	if serializer == nil {
		return nil, errors.New("serializer cannot be nil") // Serializer cannot be nil | 序列化器不能为空
	}
	if logger == nil {
		return nil, errors.New("logger cannot be nil") // Logger cannot be nil | 日志实现不能为空
	}
	return &Dep{
		serializer: serializer,
		logger:     logger,
	}, nil
}

// NewDefaultDep Creates a new Dep instance with default values | 创建一个默认赋值的 Dep 实例
func NewDefaultDep(serializer codec.Adapter, logger log.Adapter) *Dep {
	if serializer == nil {
		serializer = codec.GetDefaultSerializer() // Default serializer | 默认的序列化器
	}
	if logger == nil {
		logger = log.GetDefaultLogger() // Default logger | 默认的日志适配器
	}
	return &Dep{
		serializer: codec.GetDefaultSerializer(),
		logger:     log.GetDefaultLogger(),
	}
}

// SetSerializer Set a new codec serializer | 设置新的编解码器
func (d *Dep) SetSerializer(serializer codec.Adapter) {
	if serializer == nil {
		serializer = codec.GetDefaultSerializer() // Default serializer | 默认的序列化器
	}
	d.serializer = serializer
}

// SetLogger Set a new log adapter | 设置新的日志适配器
func (d *Dep) SetLogger(logger log.Adapter) {
	if logger == nil {
		logger = log.GetDefaultLogger() // Default logger | 默认的日志适配器
	}
	d.logger = logger
}

// GetSerializer Get the current codec serializer | 获取当前的编解码器
func (d *Dep) GetSerializer() codec.Adapter {
	return d.serializer
}

// GetLogger Get the current log adapter | 获取当前的日志适配器
func (d *Dep) GetLogger() log.Adapter {
	return d.logger
}

// ResetSerializer Reset the serializer to default | 重置序列化器为默认
func (d *Dep) ResetSerializer() {
	d.serializer = codec.GetDefaultSerializer() // Reset to default serializer | 重置为默认序列化器
}

// ResetLogger Reset the log adapter to default | 重置日志适配器为默认
func (d *Dep) ResetLogger() {
	d.logger = log.GetDefaultLogger() // Reset to default log adapter | 重置为默认日志适配器
}

// Clear Clears the current serializer and log adapter | 清空当前序列化器和日志适配器
func (d *Dep) Clear() {
	d.serializer = nil // Clear the serializer | 清空序列化器
	d.logger = nil     // Clear the log adapter | 清空日志适配器
}
