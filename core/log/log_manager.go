// @Author daixk
package log

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Logger implements ILogger + LoggerControl | 日志核心实现
type Logger struct {

	// ---- Config & State ----
	cfg   *LoggerConfig // Logger configuration | 日志配置
	cfgMu sync.RWMutex  // Config lock | 配置锁

	// ---- File IO ----
	fileMu     sync.Mutex // File write lock | 文件写锁
	curFile    *os.File   // Current log file | 当前日志文件
	curName    string     // Current file name | 当前日志文件名
	curSize    int64      // Current log size | 当前文件大小
	lastRotate time.Time  // Last rotation time | 上次切分时间

	// ---- Async Write ----
	queue chan []byte   // Async write queue | 异步写队列
	quit  chan struct{} // Stop signal | 停止信号
	wg    sync.WaitGroup

	// ---- Time Cache ----
	cacheSec int64        // Cached timestamp seconds | 缓存秒级时间戳
	cacheStr atomic.Value // Cached formatted timestamp | 缓存格式化后的时间字符串

	// ---- State ----
	closed    uint32 // Closed flag | 关闭标记
	dropCount uint64 // Dropped log counter | 队列满时丢弃日志计数

	closeOnce sync.Once // Ensure Close only executes once | 确保 Close 只执行一次
}

// NewLoggerWithConfig creates a logger instance | 使用配置创建日志器
func NewLoggerWithConfig(cfg *LoggerConfig) (*Logger, error) {
	newCfg, err := prepareConfig(cfg)
	if err != nil {
		return nil, err
	}

	l := &Logger{
		cfg:        newCfg,
		queue:      make(chan []byte, 4096),
		quit:       make(chan struct{}),
		lastRotate: time.Now(),
	}

	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		l.writerLoop()
	}()

	return l, nil
}

// ---- Logging API ----

func (l *Logger) Print(v ...any)            { l.write(LevelInfo, v...) }
func (l *Logger) Printf(f string, v ...any) { l.writef(LevelInfo, f, v...) }
func (l *Logger) Debug(v ...any)            { l.write(LevelDebug, v...) }
func (l *Logger) Debugf(f string, v ...any) { l.writef(LevelDebug, f, v...) }
func (l *Logger) Info(v ...any)             { l.write(LevelInfo, v...) }
func (l *Logger) Infof(f string, v ...any)  { l.writef(LevelInfo, f, v...) }
func (l *Logger) Warn(v ...any)             { l.write(LevelWarn, v...) }
func (l *Logger) Warnf(f string, v ...any)  { l.writef(LevelWarn, f, v...) }
func (l *Logger) Error(v ...any)            { l.write(LevelError, v...) }
func (l *Logger) Errorf(f string, v ...any) { l.writef(LevelError, f, v...) }

// write handles simple log output | 输出普通日志
func (l *Logger) write(level LogLevel, args ...any) {
	if atomic.LoadUint32(&l.closed) != 0 {
		return
	}
	cfg := l.currentCfg()
	if level < cfg.Level {
		return
	}
	l.enqueue(l.buildLine(level, args...))
}

// writef handles formatted log output | 输出格式化日志
func (l *Logger) writef(level LogLevel, format string, args ...any) {
	if atomic.LoadUint32(&l.closed) != 0 {
		return
	}
	cfg := l.currentCfg()
	if level < cfg.Level {
		return
	}
	buf := getBuf()
	_, _ = fmt.Fprintf(buf, format, args...)
	line := l.buildLine(level, buf.String())
	putBuf(buf)
	l.enqueue(line)
}

// enqueue pushes logs to async queue | 将日志推入异步队列
func (l *Logger) enqueue(b []byte) {
	if atomic.LoadUint32(&l.closed) != 0 {
		return
	}
	select {
	case l.queue <- b:
	default:
		// queue full, drop | 队列满丢弃
		atomic.AddUint64(&l.dropCount, 1)
	}
}

// ---- Build Log Line ----

// buildLine builds complete log line | 构建完整日志行
func (l *Logger) buildLine(level LogLevel, args ...any) []byte {
	cfg := l.currentCfg()
	buf := getBuf()

	// timestamp caching | 时间戳缓存
	now := time.Now()
	sec := now.Unix()

	if atomic.LoadInt64(&l.cacheSec) != sec {
		atomic.StoreInt64(&l.cacheSec, sec)
		l.cacheStr.Store(now.Format(cfg.TimeFormat))
	}

	// write time prefix | 写入时间前缀
	if ts, ok := l.cacheStr.Load().(string); ok {
		buf.WriteString(ts)
	} else {
		buf.WriteString(now.Format(cfg.TimeFormat))
	}

	buf.WriteString(" [")
	buf.WriteString(l.levelString(level))
	buf.WriteString("] ")

	buf.WriteString(cfg.Prefix)

	for i, arg := range args {
		if i > 0 {
			buf.WriteByte(' ')
		}
		l.appendValue(buf, arg)
	}

	buf.WriteByte('\n')

	// copy to new slice to avoid buffer reuse | 拷贝到新切片避免复用冲突
	out := append([]byte(nil), buf.Bytes()...)
	putBuf(buf)
	return out
}

// appendValue writes a single value | 写入单个参数
func (l *Logger) appendValue(buf *bytes.Buffer, v any) {
	switch val := v.(type) {
	case string:
		buf.WriteString(val)
	case []byte:
		buf.Write(val)
	case error:
		buf.WriteString(val.Error())

	case int, int8, int16, int32, int64:
		buf.WriteString(fmt.Sprintf("%d", val))
	case uint, uint8, uint16, uint32, uint64:
		buf.WriteString(fmt.Sprintf("%d", val))

	case float32:
		buf.WriteString(strconv.FormatFloat(float64(val), 'g', -1, 32))
	case float64:
		buf.WriteString(strconv.FormatFloat(val, 'g', -1, 64))

	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}

	case time.Time:
		buf.WriteString(val.Format(DefaultTimeFormat))

	default:
		fmt.Fprint(buf, val)
	}
}

// ---- Async Writer ----

// writerLoop processes all file IO | 异步写线程处理文件操作
func (l *Logger) writerLoop() {
	for {
		select {
		case b, ok := <-l.queue:
			if !ok {
				return
			}
			l.writeToFile(b)

		case <-l.quit:
			// drain queue | 退出前清空队列
			for {
				select {
				case b := <-l.queue:
					l.writeToFile(b)
				default:
					return
				}
			}
		}
	}
}

// writeToFile writes to current file | 写入文件
func (l *Logger) writeToFile(b []byte) {
	cfg := l.currentCfg()
	now := time.Now()

	l.fileMu.Lock()
	defer l.fileMu.Unlock()

	// open file if needed | 无文件则打开
	if err := l.ensureLogFile(now, cfg); err != nil {
		return
	}

	if l.curFile != nil {
		n, err := l.curFile.Write(b)
		if err != nil {
			_ = l.curFile.Close()
			l.curFile = nil
			_ = l.openNewFile(now, cfg)
		} else {
			l.curSize += int64(n)
		}
	}

	if cfg.Stdout {
		_, _ = os.Stdout.Write(b)
	}

	// check rotate | 检测切分
	if l.shouldRotate(now, cfg) {
		_ = l.rotate(cfg)
	}
}

// ---- File Handling ----

// ensureLogFile ensures a log file is open | 确保日志文件存在
func (l *Logger) ensureLogFile(now time.Time, cfg LoggerConfig) error {
	if l.curFile == nil {
		return l.openNewFile(now, cfg)
	}
	if cfg.RotateExpire > 0 && now.Sub(l.lastRotate) >= cfg.RotateExpire {
		return l.rotate(cfg)
	}
	return nil
}

// openNewFile opens a new log file | 打开新日志文件
func (l *Logger) openNewFile(now time.Time, cfg LoggerConfig) error {
	name := l.formatFileName(now, cfg)
	path := filepath.Join(cfg.Path, name)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return err
	}

	l.curFile = f
	l.curName = name
	l.curSize = getFileSize(f)
	l.lastRotate = now
	return nil
}

// shouldRotate checks rotation conditions | 检查是否需要切分
func (l *Logger) shouldRotate(now time.Time, cfg LoggerConfig) bool {
	if cfg.RotateSize > 0 && l.curSize >= cfg.RotateSize {
		return true
	}
	if cfg.RotateExpire > 0 && now.Sub(l.lastRotate) >= cfg.RotateExpire {
		return true
	}
	return false
}

// rotate rotates the current log file | 日志切分逻辑
func (l *Logger) rotate(cfg LoggerConfig) error {
	if l.curFile == nil {
		return nil
	}

	old := filepath.Join(cfg.Path, l.curName)
	_ = l.curFile.Sync()
	_ = l.curFile.Close()
	l.curFile = nil

	now := time.Now()
	ts := fmt.Sprintf("%s_%03d", now.Format("20060102_150405"), now.Nanosecond()/1e6)

	base := strings.TrimSuffix(l.curName, ".log")
	newName := fmt.Sprintf("%s_%s.log", base, ts)
	newPath := filepath.Join(cfg.Path, newName)

	if err := os.Rename(old, newPath); err != nil {
		_ = os.Rename(old, filepath.Join(cfg.Path, base+fmt.Sprintf("_%06d.log", rand.Intn(1_000_000))))
	}

	l.curSize = 0
	l.curName = ""
	l.lastRotate = now

	l.cleanup(cfg)
	return l.openNewFile(now, cfg)
}

// cleanup removes expired logs | 清理过期/多余日志文件
func (l *Logger) cleanup(cfg LoggerConfig) {
	// base is the fixed prefix of log files for this logger | base 为该 Logger 对应日志文件的固定前缀
	base := normalizeBaseName(cfg.FileFormat)
	if base == "" {
		base = DefaultBaseName
	}

	files, _ := filepath.Glob(filepath.Join(cfg.Path, "*.log"))
	if len(files) == 0 {
		return
	}

	var keep []struct {
		path string
		t    time.Time
	}

	now := time.Now()
	expire := time.Time{}
	if cfg.RotateBackupDays > 0 {
		expire = now.AddDate(0, 0, -cfg.RotateBackupDays)
	}

	for _, f := range files {
		info, err := os.Stat(f)
		if err != nil {
			continue
		}

		filename := filepath.Base(f)

		// 只处理以 base 开头的文件 | only handle files with the same base prefix
		if !strings.HasPrefix(filename, base) {
			continue
		}

		// 清理过期文件 | remove expired files
		if !expire.IsZero() && info.ModTime().Before(expire) {
			_ = os.Remove(f)
			continue
		}

		// 当前正在写入的文件此时尚未创建（在 rotate 之后），
		// 这里收集到的全是“备份文件”，后续按数量进行裁剪
		keep = append(keep, struct {
			path string
			t    time.Time
		}{f, info.ModTime()})
	}

	// 根据 RotateBackupLimit 限制保留的备份文件数量（不包含当前正在写的那个文件）|
	// keep only the newest RotateBackupLimit backup files (current file is not included here)
	if cfg.RotateBackupLimit > 0 && len(keep) > cfg.RotateBackupLimit {
		// 按修改时间排序，最旧的在前 | sort by time ascending
		sort.Slice(keep, func(i, j int) bool { return keep[i].t.Before(keep[j].t) })

		// 删除多余的，只保留最新的 cfg.RotateBackupLimit 个 | remove oldest extras
		for _, f := range keep[:len(keep)-cfg.RotateBackupLimit] {
			_ = os.Remove(f.path)
		}
	}
}

// formatFileName generates filename | 生成日志文件名
func (l *Logger) formatFileName(t time.Time, cfg LoggerConfig) string {
	name := cfg.FileFormat
	if name == "" {
		return fmt.Sprintf("%s_%s.log", DefaultBaseName, t.Format("2006-01-02"))
	}

	r := strings.NewReplacer(
		"{Y}", t.Format("2006"),
		"{m}", t.Format("01"),
		"{d}", t.Format("02"),
	)

	name = r.Replace(name)
	if !strings.HasSuffix(name, ".log") {
		name += ".log"
	}
	return name
}

// ---- Runtime Control ----

// SetLevel updates minimum level | 动态更新日志级别
func (l *Logger) SetLevel(level LogLevel) {
	l.cfgMu.Lock()
	if l.cfg != nil {
		l.cfg.Level = level
	}
	l.cfgMu.Unlock()
}

// SetPrefix updates prefix | 动态更新日志前缀
func (l *Logger) SetPrefix(prefix string) {
	l.cfgMu.Lock()
	if l.cfg != nil {
		l.cfg.Prefix = prefix
	}
	l.cfgMu.Unlock()
}

// SetStdout enables/disables stdout | 开关控制台输出
func (l *Logger) SetStdout(enable bool) {
	l.cfgMu.Lock()
	if l.cfg != nil {
		l.cfg.Stdout = enable
	}
	l.cfgMu.Unlock()
}

// SetConfig replaces config and reopens log file | 动态替换配置并重新创建日志文件
func (l *Logger) SetConfig(cfg *LoggerConfig) {
	newCfg, err := prepareConfig(cfg)
	if err != nil {
		return
	}

	l.cfgMu.Lock()
	l.fileMu.Lock()

	l.cfg = newCfg

	if l.curFile != nil {
		_ = l.curFile.Sync()
		_ = l.curFile.Close()
		l.curFile = nil
	}

	l.curName = ""
	l.curSize = 0
	l.lastRotate = time.Now()

	l.fileMu.Unlock()
	l.cfgMu.Unlock()
}

// Close stops logger | 关闭日志系统
func (l *Logger) Close() {
	l.closeOnce.Do(func() {
		atomic.StoreUint32(&l.closed, 1)
		close(l.quit)

		l.wg.Wait()

		l.fileMu.Lock()
		defer l.fileMu.Unlock()

		if l.curFile != nil {
			_ = l.curFile.Sync()
			_ = l.curFile.Close()
		}
	})
}

// Flush flushes file buffer | 强制刷新文件缓冲区
func (l *Logger) Flush() {
	l.fileMu.Lock()
	defer l.fileMu.Unlock()
	if l.curFile != nil {
		_ = l.curFile.Sync()
	}
}

// LogPath returns directory | 返回日志目录
func (l *Logger) LogPath() string {
	l.cfgMu.RLock()
	defer l.cfgMu.RUnlock()
	if l.cfg == nil {
		return ""
	}
	return l.cfg.Path
}

// DropCount returns dropped logs | 返回丢弃日志数量
func (l *Logger) DropCount() uint64 {
	return atomic.LoadUint64(&l.dropCount)
}

// ---- Buffer Pool ----

var bufPool = sync.Pool{
	New: func() any { return new(bytes.Buffer) },
}

func getBuf() *bytes.Buffer {
	b := bufPool.Get().(*bytes.Buffer)
	b.Reset()
	return b
}

func putBuf(b *bytes.Buffer) {
	bufPool.Put(b)
}

// ---- Helpers ----

// getFileSize returns file size | 获取文件大小
func getFileSize(f *os.File) int64 {
	info, err := f.Stat()
	if err != nil {
		return 0
	}
	return info.Size()
}

// prepareConfig applies defaults and ensures directory | 应用默认配置并确保目录存在
func prepareConfig(cfg *LoggerConfig) (*LoggerConfig, error) {
	if cfg == nil {
		cfg = &LoggerConfig{}
	}

	c := *cfg // copy

	if c.TimeFormat == "" {
		c.TimeFormat = DefaultTimeFormat
	}
	if c.FileFormat == "" {
		c.FileFormat = DefaultFileFormat
	}
	if c.Prefix == "" {
		c.Prefix = DefaultPrefix
	}
	if c.RotateSize <= 0 {
		c.RotateSize = DefaultRotateSize
	}
	if c.RotateExpire < 0 {
		c.RotateExpire = 0
	}
	if c.RotateBackupLimit <= 0 {
		c.RotateBackupLimit = DefaultRotateBackupLimit
	}
	if c.RotateBackupDays < 0 {
		c.RotateBackupDays = 0
	}

	c.Path = ensureDefaultPath(&c)

	if err := os.MkdirAll(c.Path, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	return &c, nil
}

// currentCfg returns a config snapshot | 返回当前配置快照
func (l *Logger) currentCfg() LoggerConfig {
	l.cfgMu.RLock()
	defer l.cfgMu.RUnlock()

	if l.cfg == nil {
		return LoggerConfig{}
	}
	return *l.cfg
}

// levelString converts log level to string | 将日志级别转换为字符串
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

// normalizeBaseName extracts static name | 提取基础日志文件名前缀
func normalizeBaseName(format string) string {
	if format == "" {
		return DefaultBaseName
	}

	// 去掉 .log 后缀 | strip ".log" suffix
	name := strings.TrimSuffix(format, ".log")

	// 如果包含占位符，则取第一个占位符之前的固定前缀 | if contains "{...}", take prefix before first placeholder
	if idx := strings.Index(name, "{"); idx >= 0 {
		name = name[:idx]
		// 去掉末尾的连接符（常见为 "_" 或 "-"）| trim trailing separators like "_" or "-"
		name = strings.TrimRight(name, "_- ")
	}

	name = strings.TrimSpace(name)
	if name == "" {
		return DefaultBaseName
	}
	return name
}
