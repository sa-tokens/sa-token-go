// @Author daixk 2025/12/22 15:55:00
package slog

import (
	"time"
)

// LoggerConfig defines configuration for the logger | 日志配置项，定义日志输出的行为、格式和文件管理策略
type LoggerConfig struct {
	Path              string        // Log directory path | 日志文件目录
	FileFormat        string        // Log file naming format | 日志文件命名格式
	Prefix            string        // Log line prefix | 日志前缀
	Level             LogLevel      // Minimum output level | 最低输出级别
	TimeFormat        string        // Timestamp format | 时间戳格式
	Stdout            bool          // Print logs to console | 是否输出到控制台
	RotateSize        int64         // File size threshold before rotation (bytes) | 文件滚动大小阈值（字节）
	RotateExpire      time.Duration // Rotation interval by time duration | 文件时间滚动间隔
	RotateBackupLimit int           // Maximum number of rotated backup files | 最大备份文件数量
	RotateBackupDays  int           // Retention days for old log files | 备份文件保留天数
}

// DefaultLoggerConfig returns default logger configuration | 返回默认日志配置
func DefaultLoggerConfig() *LoggerConfig {
	return &LoggerConfig{
		TimeFormat:        DefaultTimeFormat,
		FileFormat:        DefaultFileFormat,
		Prefix:            DefaultPrefix,
		Level:             LevelInfo,
		Stdout:            true,
		RotateSize:        DefaultRotateSize,
		RotateExpire:      DefaultRotateExpire,
		RotateBackupLimit: DefaultRotateBackupLimit,
		RotateBackupDays:  DefaultRotateBackupDays,
	}
}

// SetPath sets the log output directory | 设置日志输出目录
func (c *LoggerConfig) SetPath(path string) *LoggerConfig {
	c.Path = path
	return c
}

// SetFileFormat sets the log file naming format | 设置日志文件命名格式
func (c *LoggerConfig) SetFileFormat(format string) *LoggerConfig {
	c.FileFormat = format
	return c
}

// SetPrefix sets the log line prefix | 设置日志输出前缀
func (c *LoggerConfig) SetPrefix(prefix string) *LoggerConfig {
	c.Prefix = prefix
	return c
}

// SetLevel sets the minimum output log level | 设置日志最低输出级别
func (c *LoggerConfig) SetLevel(level LogLevel) *LoggerConfig {
	c.Level = level
	return c
}

// SetTimeFormat sets the timestamp format in log lines | 设置日志时间戳格式
func (c *LoggerConfig) SetTimeFormat(format string) *LoggerConfig {
	c.TimeFormat = format
	return c
}

// SetStdout enables or disables console output | 设置是否输出到控制台
func (c *LoggerConfig) SetStdout(enable bool) *LoggerConfig {
	c.Stdout = enable
	return c
}

// SetRotateSize sets the file size threshold for log rotation | 设置日志文件大小滚动阈值
func (c *LoggerConfig) SetRotateSize(size int64) *LoggerConfig {
	c.RotateSize = size
	return c
}

// SetRotateExpire sets the time-based rotation interval | 设置时间滚动间隔
func (c *LoggerConfig) SetRotateExpire(d time.Duration) *LoggerConfig {
	c.RotateExpire = d
	return c
}

// SetRotateBackupLimit sets the maximum number of backup log files retained | 设置最大备份文件数量
func (c *LoggerConfig) SetRotateBackupLimit(limit int) *LoggerConfig {
	c.RotateBackupLimit = limit
	return c
}

// SetRotateBackupDays sets the retention days for backup log files | 设置日志备份保留天数
func (c *LoggerConfig) SetRotateBackupDays(days int) *LoggerConfig {
	c.RotateBackupDays = days
	return c
}

// Clone returns a copy of the current logger configuration | 返回当前日志配置的副本
func (c *LoggerConfig) Clone() *LoggerConfig {
	if c == nil {
		return &LoggerConfig{}
	}
	copyCfg := *c
	return &copyCfg
}
