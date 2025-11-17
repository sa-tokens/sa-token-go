package log

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Logger implements ILogger + LoggerControl | 日志核心实现
type Logger struct {
	cfg         *LoggerConfig // Logger configuration | 日志配置
	mu          sync.Mutex    // Write lock | 写入锁
	curFile     *os.File      // Current log file handle | 当前文件句柄
	curFileName string        // Current log filename | 当前文件名
	curSize     int64         // Current file size | 当前文件大小
	lastRotate  time.Time     // Last rotation timestamp | 上次切分时间
}

// NewLoggerWithConfig creates a logger with given config | 创建带配置的日志实例
func NewLoggerWithConfig(cfg *LoggerConfig) (*Logger, error) {
	if cfg == nil {
		cfg = &LoggerConfig{}
	}
	if cfg.TimeFormat == "" {
		cfg.TimeFormat = DefaultTimeFormat
	}
	if cfg.FileFormat == "" {
		cfg.FileFormat = DefaultFileFormat
	}
	if cfg.Prefix == "" {
		cfg.Prefix = DefaultPrefix
	}
	cfg.Path = ensureDefaultPath(cfg)
	if err := os.MkdirAll(cfg.Path, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}
	return &Logger{cfg: cfg, lastRotate: time.Now()}, nil
}

// write writes log message to file and stdout | 写入日志信息到文件与终端
func (l *Logger) write(level LogLevel, msg string) {
	if level < l.cfg.Level {
		return // Skip lower-level logs | 忽略低于当前级别的日志
	}

	now := time.Now()
	line := fmt.Sprintf("%s [%s] %s%s\n",
		now.Format(l.cfg.TimeFormat),
		l.levelString(level),
		l.cfg.Prefix,
		msg,
	)

	if l.cfg.Stdout {
		fmt.Print(line) // Print to console | 输出到终端
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.ensureLogFile(now); err != nil {
		fmt.Fprintf(os.Stderr, "Logger error: %v\n", err)
		return
	}

	if l.curFile != nil {
		n, _ := l.curFile.WriteString(line)
		l.curSize += int64(n)
	}

	if l.shouldRotate(now) {
		_ = l.rotate()
	}
}

// ensureLogFile ensures log file exists or triggers rotation | 确保文件存在或触发滚动
func (l *Logger) ensureLogFile(now time.Time) error {
	if l.curFile == nil {
		return l.openNewFile(now)
	}
	if l.cfg.RotateExpire > 0 && now.Sub(l.lastRotate) >= l.cfg.RotateExpire {
		return l.rotate()
	}
	return nil
}

// openNewFile opens new log file for writing | 打开新日志文件
func (l *Logger) openNewFile(now time.Time) error {
	name := l.formatFileName(now)
	path := filepath.Join(l.cfg.Path, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return err
	}
	l.curFile = f
	l.curFileName = name
	l.curSize = getFileSize(f)
	l.lastRotate = now
	return nil
}

// shouldRotate determines if rotation is needed | 判断是否需要滚动切分
func (l *Logger) shouldRotate(now time.Time) bool {
	return (l.cfg.RotateSize > 0 && l.curSize >= l.cfg.RotateSize) ||
		(l.cfg.RotateExpire > 0 && now.Sub(l.lastRotate) >= l.cfg.RotateExpire)
}

// rotate performs file rotation and cleanup | 执行日志切分与清理
func (l *Logger) rotate() error {
	if l.curFile == nil {
		return nil
	}
	old := filepath.Join(l.cfg.Path, l.curFileName)
	_ = l.curFile.Close()

	// 带毫秒的时间戳 | include milliseconds for safety
	now := time.Now()
	ts := fmt.Sprintf("%s_%03d", now.Format("20060102_150405"), now.Nanosecond()/1e6)

	base := strings.TrimSuffix(l.curFileName, ".log")
	newName := fmt.Sprintf("%s_%s.log", base, ts)
	_ = os.Rename(old, filepath.Join(l.cfg.Path, newName))

	l.curFile = nil
	l.curSize = 0
	l.lastRotate = now

	l.cleanupOldLogs()
	return l.openNewFile(now)
}

// cleanupOldLogs removes expired or excessive log files | 清理过期或多余日志文件
func (l *Logger) cleanupOldLogs() {
	files, _ := filepath.Glob(filepath.Join(l.cfg.Path, "*.log"))
	if len(files) == 0 {
		return
	}

	if l.cfg.RotateBackupDays > 0 {
		expire := time.Now().AddDate(0, 0, -l.cfg.RotateBackupDays)
		for _, f := range files {
			if info, err := os.Stat(f); err == nil && info.ModTime().Before(expire) {
				_ = os.Remove(f)
			}
		}
	}

	if l.cfg.RotateBackupLimit > 0 && len(files) > l.cfg.RotateBackupLimit {
		sort.Slice(files, func(i, j int) bool {
			fi, _ := os.Stat(files[i])
			fj, _ := os.Stat(files[j])
			return fi.ModTime().Before(fj.ModTime())
		})
		for _, f := range files[:len(files)-l.cfg.RotateBackupLimit] {
			_ = os.Remove(f)
		}
	}
}

// formatFileName builds log filename based on time format | 构建日志文件名
func (l *Logger) formatFileName(t time.Time) string {
	name := l.cfg.FileFormat
	for k, v := range map[string]string{
		"{Y-m-d}": t.Format("2006-01-02"),
		"{Y}":     t.Format("2006"),
		"{m}":     t.Format("01"),
		"{d}":     t.Format("02"),
		"{H}":     t.Format("15"),
		"{i}":     t.Format("04"),
		"{s}":     t.Format("05"),
	} {
		name = strings.ReplaceAll(name, k, v)
	}
	if !strings.HasSuffix(name, ".log") {
		name += ".log"
	}
	return name
}

// getFileSize returns current file size | 获取文件大小
func getFileSize(f *os.File) int64 {
	info, err := f.Stat()
	if err != nil {
		return 0
	}
	return info.Size()
}

// levelString converts log level to string | 将日志级别转为字符串
func (l *Logger) levelString(level LogLevel) string {
	switch level {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

func (l *Logger) Print(v ...any)            { l.write(LevelInfo, fmt.Sprint(v...)) }      // 普通日志打印
func (l *Logger) Printf(f string, v ...any) { l.write(LevelInfo, fmt.Sprintf(f, v...)) }  // 普通日志格式化打印
func (l *Logger) Debug(v ...any)            { l.write(LevelDebug, fmt.Sprint(v...)) }     // 调试级别日志
func (l *Logger) Debugf(f string, v ...any) { l.write(LevelDebug, fmt.Sprintf(f, v...)) } // 调试级别格式化日志
func (l *Logger) Info(v ...any)             { l.write(LevelInfo, fmt.Sprint(v...)) }      // 信息级别日志
func (l *Logger) Infof(f string, v ...any)  { l.write(LevelInfo, fmt.Sprintf(f, v...)) }  // 信息级别格式化日志
func (l *Logger) Warn(v ...any)             { l.write(LevelWarn, fmt.Sprint(v...)) }      // 警告级别日志
func (l *Logger) Warnf(f string, v ...any)  { l.write(LevelWarn, fmt.Sprintf(f, v...)) }  // 警告级别格式化日志
func (l *Logger) Error(v ...any)            { l.write(LevelError, fmt.Sprint(v...)) }     // 错误级别日志
func (l *Logger) Errorf(f string, v ...any) { l.write(LevelError, fmt.Sprintf(f, v...)) } // 错误级别格式化日志

func (l *Logger) SetLevel(level LogLevel) { l.cfg.Level = level }   // 设置日志输出级别
func (l *Logger) SetPrefix(prefix string) { l.cfg.Prefix = prefix } // 设置日志前缀
func (l *Logger) SetStdout(enable bool)   { l.cfg.Stdout = enable } // 设置终端输出开关

// SetConfig dynamically replaces logger configuration | 动态替换日志配置
func (l *Logger) SetConfig(cfg *LoggerConfig) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cfg = cfg
}

// Close safely closes current file | 安全关闭日志文件
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.curFile != nil {
		_ = l.curFile.Close()
		l.curFile = nil
	}
}

// LogPath returns current log directory | 获取日志目录路径
func (l *Logger) LogPath() string {
	if l.cfg == nil {
		return ""
	}
	return l.cfg.Path
}

// Flush forces the log file to sync to disk | 强制刷新日志到磁盘
func (l *Logger) Flush() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.curFile != nil {
		_ = l.curFile.Sync()
	}
}

// DefaultLogger is the global shared logger | 全局默认日志实例
var DefaultLogger *Logger

func init() {
	l, err := NewBuilder().
		Prefix(DefaultPrefix).
		Level(LevelInfo).
		Stdout(true).
		Build()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[SA-TOKEN-GO] logger init failed: %v\n", err)
		l = &Logger{cfg: &LoggerConfig{Stdout: true, Prefix: DefaultPrefix}}
	}
	DefaultLogger = l
}

// Print 全局普通日志 | Global Print log
func Print(v ...any)            { DefaultLogger.Print(v...) }
func Printf(f string, v ...any) { DefaultLogger.Printf(f, v...) }

// Debug 全局调试日志 | Global Debug log
func Debug(v ...any)            { DefaultLogger.Debug(v...) }
func Debugf(f string, v ...any) { DefaultLogger.Debugf(f, v...) }

// Info 全局信息日志 | Global Info log
func Info(v ...any)            { DefaultLogger.Info(v...) }
func Infof(f string, v ...any) { DefaultLogger.Infof(f, v...) }

// Warn 全局警告日志 | Global Warn log
func Warn(v ...any)            { DefaultLogger.Warn(v...) }
func Warnf(f string, v ...any) { DefaultLogger.Warnf(f, v...) }

// Error 全局错误日志 | Global Error log
func Error(v ...any)            { DefaultLogger.Error(v...) }
func Errorf(f string, v ...any) { DefaultLogger.Errorf(f, v...) }
