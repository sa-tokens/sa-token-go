// @Author daixk 2025/11/24 21:42:00
package log

import (
	"sync"
)

// Global logger with default NOP implementation | 默认使用无输出的 NOP 日志器
var (
	GlobalLogger ILogger = &NopLogger{}
	logMu        sync.RWMutex
)

// SetGlobalLogger sets the global logger | 设置全局日志器
func SetGlobalLogger(l ILogger) {
	if l == nil {
		return
	}
	logMu.Lock()
	GlobalLogger = l
	logMu.Unlock()
}

// getLogger safely returns global logger | 获取全局日志器（内部用）
func getLogger() ILogger {
	logMu.RLock()
	l := GlobalLogger
	logMu.RUnlock()
	return l
}

// NopLogger is a logger implementation that performs no operations |  用于禁用所有日志输出的空日志器
type NopLogger struct{}

// NewNopLogger creates a new no-op logger | 创建一个空日志器实例
func NewNopLogger() ILogger {
	return &NopLogger{}
}

// ---- Implement ILogger Interface | 实现 ILogger 接口 ----

func (n *NopLogger) Print(v ...any)                 {}
func (n *NopLogger) Printf(format string, v ...any) {}

func (n *NopLogger) Debug(v ...any)                 {}
func (n *NopLogger) Debugf(format string, v ...any) {}

func (n *NopLogger) Info(v ...any)                 {}
func (n *NopLogger) Infof(format string, v ...any) {}

func (n *NopLogger) Warn(v ...any)                 {}
func (n *NopLogger) Warnf(format string, v ...any) {}

func (n *NopLogger) Error(v ...any)                 {}
func (n *NopLogger) Errorf(format string, v ...any) {}
