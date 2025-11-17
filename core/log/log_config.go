package log

import (
	"os"
	"path/filepath"
	"time"
)

// LogLevel defines severity level | 日志级别定义
type LogLevel int

const (
	LevelDebug LogLevel = iota // Debug level | 调试级别
	LevelInfo                  // Info level | 信息级别
	LevelWarn                  // Warn level | 警告级别
	LevelError                 // Error level | 错误级别（最高）
)

const (
	DefaultPrefix            = "[SA-TOKEN-GO] "
	DefaultFileFormat        = "{Y-m-d}.log"         // Default log filename format | 默认文件命名格式
	DefaultTimeFormat        = "2006-01-02 15:04:05" // Default time format | 默认时间格式
	DefaultDirName           = "sa_token_go_log"     // Default log directory name | 默认日志目录名
	DefaultRotateSize        = 10 * 1024 * 1024      // Rotate threshold (10MB) | 文件滚动大小阈值
	DefaultRotateExpire      = 24 * time.Hour        // Rotate by time interval (1 day) | 时间滚动间隔
	DefaultRotateBackupLimit = 10                    // Max number of backups | 最大备份数量
	DefaultRotateBackupDays  = 7                     // Retain logs for 7 days | 备份保留天数
)

// LoggerConfig defines configuration for logger | 日志配置项
type LoggerConfig struct {
	Path              string        // Log directory | 日志文件目录
	FileFormat        string        // File naming format | 文件命名格式
	Prefix            string        // Log prefix | 日志前缀
	Level             LogLevel      // Output level | 输出级别
	TimeFormat        string        // Timestamp format | 时间格式
	Stdout            bool          // Output to console | 是否输出到控制台
	RotateSize        int64         // Max file size before rotation | 文件大小滚动阈值（字节）
	RotateExpire      time.Duration // Time interval for rotation | 时间间隔滚动切分
	RotateBackupLimit int           // Max number of backup files | 最大备份数量
	RotateBackupDays  int           // Backup retention days | 备份保留天数
}

// LoggerBuilder helps construct a Logger with chainable methods | 链式构建器
type LoggerBuilder struct {
	cfg *LoggerConfig
}

// NewBuilder creates a builder with default config | 创建带默认配置的构建器
func NewBuilder() *LoggerBuilder {
	return &LoggerBuilder{
		cfg: &LoggerConfig{
			TimeFormat:        DefaultTimeFormat,
			FileFormat:        DefaultFileFormat,
			Level:             LevelInfo,
			Stdout:            true,
			RotateSize:        DefaultRotateSize,
			RotateExpire:      DefaultRotateExpire,
			RotateBackupLimit: DefaultRotateBackupLimit,
			RotateBackupDays:  DefaultRotateBackupDays,
		},
	}
}

func (b *LoggerBuilder) Path(path string) *LoggerBuilder         { b.cfg.Path = path; return b }         // Set log directory | 设置日志目录
func (b *LoggerBuilder) FileFormat(format string) *LoggerBuilder { b.cfg.FileFormat = format; return b } // Set file naming format | 设置文件命名格式
func (b *LoggerBuilder) Prefix(prefix string) *LoggerBuilder     { b.cfg.Prefix = prefix; return b }     // Set prefix | 设置日志前缀
func (b *LoggerBuilder) Level(level LogLevel) *LoggerBuilder     { b.cfg.Level = level; return b }       // Set minimum output level | 设置日志级别
func (b *LoggerBuilder) TimeFormat(format string) *LoggerBuilder { b.cfg.TimeFormat = format; return b } // Set timestamp format | 设置时间格式
func (b *LoggerBuilder) Stdout(enable bool) *LoggerBuilder       { b.cfg.Stdout = enable; return b }     // Enable console output | 是否输出到控制台
func (b *LoggerBuilder) RotateSize(size int64) *LoggerBuilder    { b.cfg.RotateSize = size; return b }   // Set rotate size | 设置文件滚动大小阈值
func (b *LoggerBuilder) RotateExpire(d time.Duration) *LoggerBuilder {
	b.cfg.RotateExpire = d
	return b
} // Set time interval rotation | 设置时间滚动间隔
func (b *LoggerBuilder) RotateBackupLimit(limit int) *LoggerBuilder {
	b.cfg.RotateBackupLimit = limit
	return b
} // Set max backup count | 设置最大备份数量
func (b *LoggerBuilder) RotateBackupDays(days int) *LoggerBuilder {
	b.cfg.RotateBackupDays = days
	return b
} // Set backup retention days | 设置备份保留天数

// Build constructs a Logger instance | 构建日志实例
func (b *LoggerBuilder) Build() (*Logger, error) { return NewLoggerWithConfig(b.cfg) }

// BuildMust constructs a Logger or panics | 构建日志实例（失败则panic）
func (b *LoggerBuilder) BuildMust() *Logger {
	l, err := NewLoggerWithConfig(b.cfg)
	if err != nil {
		panic(err)
	}
	return l
}

// ensureDefaultPath ensures log directory exists | 确保日志目录存在
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
