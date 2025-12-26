// @Author daixk 2025/12/22 15:56:00
package slog

import (
	"time"

	"github.com/click33/sa-token-go/core/adapter"
)

// LogLevel is an alias for adapter.LogLevel | 日志级别别名
type LogLevel = adapter.LogLevel

// Log level constants | 日志级别常量
const (
	LevelDebug = adapter.LogLevelDebug // Debug level | 调试级别
	LevelInfo  = adapter.LogLevelInfo  // Info level | 信息级别
	LevelWarn  = adapter.LogLevelWarn  // Warn level | 警告级别
	LevelError = adapter.LogLevelError // Error level | 错误级别（最高）
)

const (
	DefaultPrefix            = "[SA-TOKEN-GO] "              // Default log prefix | 默认日志前缀
	DefaultFileFormat        = "SA-TOKEN-GO_{Y}-{m}-{d}.log" // Default log filename format | 默认文件命名格式
	DefaultTimeFormat        = "2006-01-02 15:04:05"         // Default time format | 默认时间格式
	DefaultDirName           = "sa_token_go_logs"            // Default log directory name | 默认日志目录名
	DefaultBaseName          = "SA-TOKEN-GO"                 // Default log filename prefix | 默认日志文件基础前缀
	DefaultQueueSize         = 4096                          // Default async queue size | 默认异步队列大小
	DefaultRotateSize        = 10 * 1024 * 1024              // Rotate threshold (10MB) | 文件滚动大小阈值
	DefaultRotateExpire      = 24 * time.Hour                // Rotate by time interval (1 day) | 时间滚动间隔
	DefaultRotateBackupLimit = 10                            // Max number of backups | 最大备份数量
	DefaultRotateBackupDays  = 7                             // Retain logs for 7 days | 备份保留天数
)
