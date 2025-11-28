// @Author daixk 2025/11/27 21:11:00
package log

import (
	"sync/atomic"
)

// loggerHolder wraps Adapter to ensure atomic.Value type consistency | 包装 Adapter 以确保 atomic.Value 类型一致性
type loggerHolder struct {
	l Adapter
}

// using atomic.Value for lock-free fast read | 使用 atomic.Value 实现无锁快速读取
var defaultLogger atomic.Value

func init() {
	// 初始化为 NopLogger，确保类型一致：loggerHolder
	defaultLogger.Store(loggerHolder{l: &NopLogger{}})
}

// SetGlobalLogger sets global logger | 设置全局日志器
func SetGlobalLogger(l Adapter) {
	if l == nil {
		return
	}

	// atomic 替换，但存的是结构体 loggerHolder，类型始终一致
	defaultLogger.Store(loggerHolder{l: l})
}

// getLogger returns the logger | 获取当前日志器
func getLogger() Adapter {
	return defaultLogger.Load().(loggerHolder).l
}

// -------------------- Global Logging APIs --------------------

func Print(v ...any)                 { getLogger().Print(v...) }
func Printf(format string, v ...any) { getLogger().Printf(format, v...) }

func Debug(v ...any)                 { getLogger().Debug(v...) }
func Debugf(format string, v ...any) { getLogger().Debugf(format, v...) }

func Info(v ...any)                 { getLogger().Info(v...) }
func Infof(format string, v ...any) { getLogger().Infof(format, v...) }

func Warn(v ...any)                 { getLogger().Warn(v...) }
func Warnf(format string, v ...any) { getLogger().Warnf(format, v...) }

func Error(v ...any)                 { getLogger().Error(v...) }
func Errorf(format string, v ...any) { getLogger().Errorf(format, v...) }
