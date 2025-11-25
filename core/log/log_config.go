package log

import (
	"os"
	"path/filepath"
	"time"
)

// LogLevel defines severity level | 日志级别定义
type LogLevel int

const (
	LevelDebug LogLevel = iota + 1 // Debug level | 调试级别
	LevelInfo                      // Info level | 信息级别
	LevelWarn                      // Warn level | 警告级别
	LevelError                     // Error level | 错误级别（最高）
)

const (
	DefaultPrefix            = "[SA-TOKEN-GO] "              // Default log prefix | 默认日志前缀
	DefaultFileFormat        = "SA-TOKEN-GO_{Y}-{m}-{d}.log" // Default log filename format | 默认文件命名格式
	DefaultTimeFormat        = "2006-01-02 15:04:05"         // Default time format | 默认时间格式
	DefaultDirName           = "sa_token_go_logs"            // Default log directory name | 默认日志目录名
	DefaultBaseName          = "SA-TOKEN-GO"                 // Default log filename prefix | 默认日志文件基础前缀
	DefaultRotateSize        = 10 * 1024 * 1024              // Rotate threshold (10MB) | 文件滚动大小阈值
	DefaultRotateExpire      = 24 * time.Hour                // Rotate by time interval (1 day) | 时间滚动间隔
	DefaultRotateBackupLimit = 10                            // Max number of backups | 最大备份数量
	DefaultRotateBackupDays  = 7                             // Retain logs for 7 days | 备份保留天数
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

// LoggerBuilder provides a fluent interface for building logger instances | 链式日志构建器
type LoggerBuilder struct {
	cfg *LoggerConfig
}

// NewBuilder creates a new LoggerBuilder with default configuration | 创建一个带默认配置的日志构建器
func NewBuilder() *LoggerBuilder {
	return &LoggerBuilder{
		cfg: &LoggerConfig{
			TimeFormat:        DefaultTimeFormat,
			FileFormat:        DefaultFileFormat,
			Prefix:            DefaultPrefix,
			Level:             LevelInfo,
			Stdout:            true,
			RotateSize:        DefaultRotateSize,
			RotateExpire:      DefaultRotateExpire,
			RotateBackupLimit: DefaultRotateBackupLimit,
			RotateBackupDays:  DefaultRotateBackupDays,
		},
	}
}

// Path sets the log output directory | 设置日志输出目录
func (b *LoggerBuilder) Path(path string) *LoggerBuilder {
	b.cfg.Path = path
	return b
}

// FileFormat sets the log file naming format | 设置日志文件命名格式
func (b *LoggerBuilder) FileFormat(format string) *LoggerBuilder {
	b.cfg.FileFormat = format
	return b
}

// Prefix sets the log line prefix | 设置日志输出前缀
func (b *LoggerBuilder) Prefix(prefix string) *LoggerBuilder {
	b.cfg.Prefix = prefix
	return b
}

// Level sets the minimum output log level | 设置日志最低输出级别
func (b *LoggerBuilder) Level(level LogLevel) *LoggerBuilder {
	b.cfg.Level = level
	return b
}

// TimeFormat sets the timestamp format in log lines | 设置日志时间戳格式
func (b *LoggerBuilder) TimeFormat(format string) *LoggerBuilder {
	b.cfg.TimeFormat = format
	return b
}

// Stdout enables or disables console output | 设置是否输出到控制台
func (b *LoggerBuilder) Stdout(enable bool) *LoggerBuilder {
	b.cfg.Stdout = enable
	return b
}

// RotateSize sets the file size threshold for log rotation | 设置日志文件大小滚动阈值
func (b *LoggerBuilder) RotateSize(size int64) *LoggerBuilder {
	b.cfg.RotateSize = size
	return b
}

// RotateExpire sets the time-based rotation interval | 设置时间滚动间隔
func (b *LoggerBuilder) RotateExpire(d time.Duration) *LoggerBuilder {
	b.cfg.RotateExpire = d
	return b
}

// RotateBackupLimit sets the maximum number of backup log files retained | 设置最大备份文件数量
func (b *LoggerBuilder) RotateBackupLimit(limit int) *LoggerBuilder {
	b.cfg.RotateBackupLimit = limit
	return b
}

// RotateBackupDays sets the retention days for backup log files | 设置日志备份保留天数
func (b *LoggerBuilder) RotateBackupDays(days int) *LoggerBuilder {
	b.cfg.RotateBackupDays = days
	return b
}

// Build creates a new Logger instance with the configured options | 构建 Logger 实例，返回错误而不是 panic
func (b *LoggerBuilder) Build() (*Logger, error) {
	return NewLoggerWithConfig(b.cloneConfig())
}

// BuildMust creates a new Logger instance or panics if creation fails | 构建 Logger 实例（若失败则 panic）
func (b *LoggerBuilder) BuildMust() *Logger {
	l, err := NewLoggerWithConfig(b.cloneConfig())
	if err != nil {
		panic(err)
	}
	return l
}

// cloneConfig returns a safe copy of the builder’s current configuration | 复制当前构建器配置，确保构建过程安全独立
func (b *LoggerBuilder) cloneConfig() *LoggerConfig {
	if b == nil || b.cfg == nil {
		return &LoggerConfig{}
	}
	copyCfg := *b.cfg
	return &copyCfg
}

// ensureDefaultPath ensures the log directory exists; if not set, uses the default path | 确保日志目录存在；如果未设置则使用默认路径
func ensureDefaultPath(cfg *LoggerConfig) string {
	if cfg.Path != "" {
		return cfg.Path
	}
	wd, err := os.Getwd()
	if err != nil {
		wd = "."
	}
	path := filepath.Join(wd, DefaultDirName)
	_ = os.MkdirAll(path, 0755)
	return path
}
