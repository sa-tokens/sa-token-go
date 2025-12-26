// @Author daixk
package slog

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============ LogLevel Tests | 日志级别测试 ============

func TestLogLevel_String(t *testing.T) {
	tests := []struct {
		level    LogLevel
		expected string
	}{
		{LevelDebug, "DEBUG"},
		{LevelInfo, "INFO"},
		{LevelWarn, "WARN"},
		{LevelError, "ERROR"},
		{LogLevel(0), "UNKNOWN"},
		{LogLevel(100), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.level.String(); got != tt.expected {
				t.Errorf("LogLevel.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// ============ LoggerConfig Tests | 配置测试 ============

func TestDefaultLoggerConfig(t *testing.T) {
	cfg := DefaultLoggerConfig()

	if cfg.TimeFormat != DefaultTimeFormat {
		t.Errorf("TimeFormat = %v, want %v", cfg.TimeFormat, DefaultTimeFormat)
	}
	if cfg.FileFormat != DefaultFileFormat {
		t.Errorf("FileFormat = %v, want %v", cfg.FileFormat, DefaultFileFormat)
	}
	if cfg.Prefix != DefaultPrefix {
		t.Errorf("Prefix = %v, want %v", cfg.Prefix, DefaultPrefix)
	}
	if cfg.Level != LevelInfo {
		t.Errorf("Level = %v, want %v", cfg.Level, LevelInfo)
	}
	if !cfg.Stdout {
		t.Error("Stdout should be true by default")
	}
	if cfg.StdoutOnly {
		t.Error("StdoutOnly should be false by default")
	}
	if cfg.QueueSize != DefaultQueueSize {
		t.Errorf("QueueSize = %v, want %v", cfg.QueueSize, DefaultQueueSize)
	}
	if cfg.RotateSize != DefaultRotateSize {
		t.Errorf("RotateSize = %v, want %v", cfg.RotateSize, DefaultRotateSize)
	}
}

func TestLoggerConfig_Setters(t *testing.T) {
	cfg := &LoggerConfig{}
	testPath := "test_logs_path"

	cfg.SetPath(testPath).
		SetFileFormat("test_{Y}-{m}-{d}.log").
		SetPrefix("[TEST] ").
		SetLevel(LevelDebug).
		SetTimeFormat("2006-01-02").
		SetStdout(true).
		SetStdoutOnly(false).
		SetQueueSize(1024).
		SetRotateSize(1024 * 1024).
		SetRotateExpire(time.Hour).
		SetRotateBackupLimit(5).
		SetRotateBackupDays(3)

	if cfg.Path != testPath {
		t.Errorf("Path = %v, want %v", cfg.Path, testPath)
	}
	if cfg.FileFormat != "test_{Y}-{m}-{d}.log" {
		t.Errorf("FileFormat = %v", cfg.FileFormat)
	}
	if cfg.Prefix != "[TEST] " {
		t.Errorf("Prefix = %v", cfg.Prefix)
	}
	if cfg.Level != LevelDebug {
		t.Errorf("Level = %v", cfg.Level)
	}
	if cfg.QueueSize != 1024 {
		t.Errorf("QueueSize = %v", cfg.QueueSize)
	}
	if cfg.RotateBackupLimit != 5 {
		t.Errorf("RotateBackupLimit = %v", cfg.RotateBackupLimit)
	}
}

func TestLoggerConfig_SetStdoutOnly(t *testing.T) {
	cfg := &LoggerConfig{Stdout: false}

	cfg.SetStdoutOnly(true)

	if !cfg.Stdout {
		t.Error("SetStdoutOnly(true) should also set Stdout to true")
	}
	if !cfg.StdoutOnly {
		t.Error("StdoutOnly should be true")
	}
}

func TestLoggerConfig_Clone(t *testing.T) {
	original := DefaultLoggerConfig()
	original.Path = "original_path"

	cloned := original.Clone()

	if cloned.Path != original.Path {
		t.Errorf("Clone().Path = %v, want %v", cloned.Path, original.Path)
	}

	// Modify clone should not affect original
	cloned.Path = "cloned_path"
	if original.Path == cloned.Path {
		t.Error("Modifying clone should not affect original")
	}
}

func TestLoggerConfig_Clone_Nil(t *testing.T) {
	var cfg *LoggerConfig
	cloned := cfg.Clone()

	if cloned == nil {
		t.Error("Clone of nil should return empty config, not nil")
	}
}

// ============ Logger Creation Tests | 日志器创建测试 ============

func TestNewLoggerWithConfig_StdoutOnly(t *testing.T) {
	cfg := &LoggerConfig{
		Stdout:     true,
		StdoutOnly: true,
		QueueSize:  DefaultQueueSize,
	}

	logger, err := NewLoggerWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewLoggerWithConfig() error = %v", err)
	}
	defer logger.Close()

	// StdoutOnly mode should not create directory
	if logger.LogPath() != "" {
		t.Errorf("StdoutOnly mode should have empty path, got %v", logger.LogPath())
	}
}

func TestNewLoggerWithConfig_WithPath(t *testing.T) {
	tmpDir := t.TempDir()
	//tmpDir, _ := os.Getwd()

	cfg := DefaultLoggerConfig()
	cfg.Path = tmpDir
	cfg.Stdout = false

	logger, err := NewLoggerWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewLoggerWithConfig() error = %v", err)
	}
	defer logger.Close()

	if logger.LogPath() != tmpDir {
		t.Errorf("LogPath() = %v, want %v", logger.LogPath(), tmpDir)
	}
}

func TestNewLoggerWithConfig_NilConfig(t *testing.T) {
	// Should create logger with default config
	logger, err := NewLoggerWithConfig(nil)
	if err != nil {
		t.Fatalf("NewLoggerWithConfig(nil) error = %v", err)
	}
	defer logger.Close()

	// Clean up default directory
	defer os.RemoveAll(logger.LogPath())
}

func TestNewLoggerWithConfig_InvalidPath(t *testing.T) {
	cfg := DefaultLoggerConfig()
	// Use invalid path (NUL is invalid on Windows, /dev/null/invalid on Unix)
	cfg.Path = string([]byte{0}) // Null byte is invalid in paths

	_, err := NewLoggerWithConfig(cfg)
	if err == nil {
		t.Error("Expected error for invalid path")
	}
}

// ============ Logging Tests | 日志记录测试 ============

func TestLogger_AllLevels(t *testing.T) {
	tmpDir := t.TempDir()
	//tmpDir, _ := os.Getwd()

	cfg := &LoggerConfig{
		Path:       tmpDir,
		Level:      LevelDebug,
		Stdout:     false,
		FileFormat: "test.log",
		QueueSize:  100,
	}

	logger, err := NewLoggerWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewLoggerWithConfig() error = %v", err)
	}

	// Log at all levels
	logger.Debug("debug message")
	logger.Debugf("debug formatted %d", 1)
	logger.Info("info message")
	logger.Infof("info formatted %d", 2)
	logger.Warn("warn message")
	logger.Warnf("warn formatted %d", 3)
	logger.Error("error message")
	logger.Errorf("error formatted %d", 4)
	logger.Print("print message")
	logger.Printf("print formatted %d", 5)

	logger.Close()

	// Read log file and verify
	content, err := os.ReadFile(filepath.Join(tmpDir, "test.log"))
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	lines := strings.Split(string(content), "\n")
	expectedCount := 10 // 5 pairs of log calls

	actualCount := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			actualCount++
		}
	}

	if actualCount != expectedCount {
		t.Errorf("Expected %d log lines, got %d", expectedCount, actualCount)
	}

	// Verify level filtering works
	if !strings.Contains(string(content), "[DEBUG]") {
		t.Error("Should contain DEBUG logs")
	}
	if !strings.Contains(string(content), "[INFO]") {
		t.Error("Should contain INFO logs")
	}
	if !strings.Contains(string(content), "[WARN]") {
		t.Error("Should contain WARN logs")
	}
	if !strings.Contains(string(content), "[ERROR]") {
		t.Error("Should contain ERROR logs")
	}
}

func TestLogger_LevelFiltering(t *testing.T) {
	tmpDir := t.TempDir()
	//tmpDir, _ := os.Getwd()

	cfg := &LoggerConfig{
		Path:       tmpDir,
		Level:      LevelWarn, // Only WARN and ERROR
		Stdout:     false,
		FileFormat: "test.log",
		QueueSize:  100,
	}

	logger, err := NewLoggerWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewLoggerWithConfig() error = %v", err)
	}

	logger.Debug("should not appear")
	logger.Info("should not appear")
	logger.Warn("should appear")
	logger.Error("should appear")

	logger.Close()

	content, err := os.ReadFile(filepath.Join(tmpDir, "test.log"))
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	if strings.Contains(string(content), "[DEBUG]") {
		t.Error("Should NOT contain DEBUG logs")
	}
	if strings.Contains(string(content), "[INFO]") {
		t.Error("Should NOT contain INFO logs")
	}
	if !strings.Contains(string(content), "[WARN]") {
		t.Error("Should contain WARN logs")
	}
	if !strings.Contains(string(content), "[ERROR]") {
		t.Error("Should contain ERROR logs")
	}
}

// ============ appendValue Tests | 值追加测试 ============

func TestAppendValue_AllTypes(t *testing.T) {
	tests := []struct {
		name     string
		value    any
		expected string
	}{
		{"nil", nil, "<nil>"},
		{"string", "hello", "hello"},
		{"bytes", []byte("world"), "world"},
		{"error", errors.New("test error"), "test error"},
		{"nil error", error(nil), "<nil>"},
		{"int", 42, "42"},
		{"int8", int8(-8), "-8"},
		{"int16", int16(-16), "-16"},
		{"int32", int32(-32), "-32"},
		{"int64", int64(-64), "-64"},
		{"uint", uint(42), "42"},
		{"uint8", uint8(8), "8"},
		{"uint16", uint16(16), "16"},
		{"uint32", uint32(32), "32"},
		{"uint64", uint64(64), "64"},
		{"float32", float32(3.14), "3.14"},
		{"float64", float64(3.14159), "3.14159"},
		{"bool true", true, "true"},
		{"bool false", false, "false"},
		{"time", time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC), "2025-01-01 12:00:00"},
		{"struct", struct{ Name string }{"test"}, "{test}"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			appendValue(buf, tt.value)

			if got := buf.String(); got != tt.expected {
				t.Errorf("appendValue() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// ============ Runtime Control Tests | 运行时控制测试 ============

func TestLogger_SetLevel(t *testing.T) {
	cfg := &LoggerConfig{
		Stdout:     true,
		StdoutOnly: true,
		QueueSize:  DefaultQueueSize,
	}
	logger, _ := NewLoggerWithConfig(cfg)
	defer logger.Close()

	logger.SetLevel(LevelError)

	currentCfg := logger.currentCfg()
	if currentCfg.Level != LevelError {
		t.Errorf("Level = %v, want %v", currentCfg.Level, LevelError)
	}
}

func TestLogger_SetPrefix(t *testing.T) {
	cfg := &LoggerConfig{
		Stdout:     true,
		StdoutOnly: true,
		QueueSize:  DefaultQueueSize,
	}
	logger, _ := NewLoggerWithConfig(cfg)
	defer logger.Close()

	logger.SetPrefix("[NEW] ")

	currentCfg := logger.currentCfg()
	if currentCfg.Prefix != "[NEW] " {
		t.Errorf("Prefix = %v, want [NEW] ", currentCfg.Prefix)
	}
}

func TestLogger_SetStdout(t *testing.T) {
	cfg := &LoggerConfig{
		Stdout:     true,
		StdoutOnly: true,
		QueueSize:  DefaultQueueSize,
	}
	logger, _ := NewLoggerWithConfig(cfg)
	defer logger.Close()

	logger.SetStdout(false)

	currentCfg := logger.currentCfg()
	if currentCfg.Stdout {
		t.Error("Stdout should be false")
	}
}

func TestLogger_SetConfig(t *testing.T) {
	tmpDir := t.TempDir()
	//tmpDir, _ := os.Getwd()

	cfg := &LoggerConfig{
		Path:       tmpDir,
		Stdout:     false,
		FileFormat: "old.log",
		QueueSize:  100,
	}

	logger, _ := NewLoggerWithConfig(cfg)
	defer logger.Close()

	logger.Info("old log")

	// Change config
	newCfg := &LoggerConfig{
		Path:       tmpDir,
		Stdout:     false,
		FileFormat: "new.log",
		Prefix:     "[NEW] ",
		QueueSize:  100,
	}

	logger.SetConfig(newCfg)
	logger.Info("new log")

	// Wait for async write
	time.Sleep(100 * time.Millisecond)
	logger.Flush()
}

// ============ Concurrent Tests | 并发测试 ============

func TestLogger_ConcurrentWrite(t *testing.T) {
	tmpDir := t.TempDir()
	//tmpDir, _ := os.Getwd()

	cfg := &LoggerConfig{
		Path:       tmpDir,
		Level:      LevelDebug,
		Stdout:     false,
		FileFormat: "concurrent.log",
		QueueSize:  1000,
	}

	logger, err := NewLoggerWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewLoggerWithConfig() error = %v", err)
	}

	var wg sync.WaitGroup
	goroutines := 10
	logsPerGoroutine := 100

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < logsPerGoroutine; j++ {
				logger.Infof("goroutine %d, log %d", id, j)
			}
		}(i)
	}

	wg.Wait()
	logger.Close()

	content, err := os.ReadFile(filepath.Join(tmpDir, "concurrent.log"))
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	expectedLines := goroutines * logsPerGoroutine

	if len(lines) != expectedLines {
		t.Errorf("Expected %d lines, got %d", expectedLines, len(lines))
	}
}

// ============ Close Tests | 关闭测试 ============

func TestLogger_DoubleClose(t *testing.T) {
	cfg := &LoggerConfig{
		Stdout:     true,
		StdoutOnly: true,
		QueueSize:  DefaultQueueSize,
	}
	logger, _ := NewLoggerWithConfig(cfg)

	// Should not panic on double close
	logger.Close()
	logger.Close()
}

func TestLogger_WriteAfterClose(t *testing.T) {
	cfg := &LoggerConfig{
		Stdout:     true,
		StdoutOnly: true,
		QueueSize:  DefaultQueueSize,
	}
	logger, _ := NewLoggerWithConfig(cfg)
	logger.Close()

	// Should not panic
	logger.Info("after close")
	logger.Infof("after close %d", 1)
}

// ============ DropCount Tests | 丢弃计数测试 ============

func TestLogger_DropCount(t *testing.T) {
	cfg := &LoggerConfig{
		Stdout:     true,
		StdoutOnly: true,
		QueueSize:  1, // Very small queue
	}

	logger, _ := NewLoggerWithConfig(cfg)

	initial := logger.DropCount()
	if initial != 0 {
		t.Errorf("Initial DropCount = %v, want 0", initial)
	}

	// Flood the logger to potentially cause drops
	for i := 0; i < 100; i++ {
		logger.Info("flood message")
	}

	logger.Close()

	// DropCount should be accessible after close
	_ = logger.DropCount()
}

// ============ Time Cache Tests | 时间缓存测试 ============

func TestLogger_TimeCache(t *testing.T) {
	tmpDir := t.TempDir()
	//tmpDir, _ := os.Getwd()

	cfg := &LoggerConfig{
		Path:       tmpDir,
		Level:      LevelDebug,
		Stdout:     false,
		FileFormat: "timecache.log",
		QueueSize:  100,
	}

	logger, _ := NewLoggerWithConfig(cfg)

	// Write multiple logs in same second - should use cache
	for i := 0; i < 10; i++ {
		logger.Info("same second log")
	}

	logger.Close()

	content, err := os.ReadFile(filepath.Join(tmpDir, "timecache.log"))
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 10 {
		t.Errorf("Expected 10 lines, got %d", len(lines))
	}
}

// ============ File Rotation Tests | 文件轮转测试 ============

func TestLogger_RotateBySize(t *testing.T) {
	tmpDir := t.TempDir()
	//tmpDir, _ := os.Getwd()

	cfg := &LoggerConfig{
		Path:              tmpDir,
		Level:             LevelDebug,
		Stdout:            false,
		FileFormat:        "rotate.log",
		RotateSize:        500, // Very small for testing
		RotateBackupLimit: 3,
		QueueSize:         100,
	}

	logger, _ := NewLoggerWithConfig(cfg)

	// Write enough to trigger rotation
	for i := 0; i < 100; i++ {
		logger.Infof("rotation test message number %d with some padding text", i)
	}

	logger.Close()

	// Wait for async cleanup
	time.Sleep(200 * time.Millisecond)

	// Check for rotated files
	files, _ := filepath.Glob(filepath.Join(tmpDir, "*.log"))
	if len(files) == 0 {
		t.Error("Expected at least one log file")
	}

	t.Logf("Found %d log files after rotation", len(files))
}

// ============ Format Tests | 格式测试 ============

func TestFormatFileName(t *testing.T) {
	logger := &Logger{}

	tests := []struct {
		format   string
		time     time.Time
		expected string
	}{
		{
			format:   "app_{Y}-{m}-{d}.log",
			time:     time.Date(2025, 6, 15, 0, 0, 0, 0, time.UTC),
			expected: "app_2025-06-15.log",
		},
		{
			format:   "log_{Y}{m}{d}",
			time:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			expected: "log_20250101.log",
		},
		{
			format:   "",
			time:     time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC),
			expected: "SA-TOKEN-GO_2025-12-31.log",
		},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			cfg := LoggerConfig{FileFormat: tt.format}
			got := logger.formatFileName(tt.time, cfg)
			if got != tt.expected {
				t.Errorf("formatFileName() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNormalizeBaseName(t *testing.T) {
	tests := []struct {
		format   string
		expected string
	}{
		{"SA-TOKEN-GO_{Y}-{m}-{d}.log", "SA-TOKEN-GO"},
		{"app_{Y}{m}{d}.log", "app"},
		{"mylog-{Y}-{m}-{d}.log", "mylog"},
		{"simple.log", "simple"},
		{"{Y}-{m}-{d}.log", DefaultBaseName},
		{"", DefaultBaseName},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			got := normalizeBaseName(tt.format)
			if got != tt.expected {
				t.Errorf("normalizeBaseName(%q) = %v, want %v", tt.format, got, tt.expected)
			}
		})
	}
}

// ============ Benchmark Tests | 性能测试 ============

func BenchmarkLogger_Info(b *testing.B) {
	cfg := &LoggerConfig{
		Stdout:     false,
		StdoutOnly: true,
		QueueSize:  DefaultQueueSize,
	}

	logger, _ := NewLoggerWithConfig(cfg)
	defer logger.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("benchmark message")
	}
}

func BenchmarkLogger_Infof(b *testing.B) {
	cfg := &LoggerConfig{
		Stdout:     false,
		StdoutOnly: true,
		QueueSize:  DefaultQueueSize,
	}

	logger, _ := NewLoggerWithConfig(cfg)
	defer logger.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Infof("benchmark message %d", i)
	}
}

func BenchmarkLogger_Concurrent(b *testing.B) {
	cfg := &LoggerConfig{
		Stdout:     false,
		StdoutOnly: true,
		QueueSize:  DefaultQueueSize,
	}

	logger, _ := NewLoggerWithConfig(cfg)
	defer logger.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			logger.Info("concurrent benchmark")
		}
	})
}

func BenchmarkAppendValue_String(b *testing.B) {
	buf := &bytes.Buffer{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		appendValue(buf, "test string")
	}
}

func BenchmarkAppendValue_Int(b *testing.B) {
	buf := &bytes.Buffer{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		appendValue(buf, 12345678)
	}
}

func BenchmarkAppendValue_Float(b *testing.B) {
	buf := &bytes.Buffer{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		appendValue(buf, 3.14159265359)
	}
}

// ============ Edge Cases | 边界情况 ============

func TestLogger_EmptyMessage(t *testing.T) {
	tmpDir := t.TempDir()
	//tmpDir, _ := os.Getwd()

	cfg := &LoggerConfig{
		Path:       tmpDir,
		Level:      LevelDebug,
		Stdout:     false,
		FileFormat: "empty.log",
		QueueSize:  100,
	}

	logger, _ := NewLoggerWithConfig(cfg)
	logger.Info("")
	logger.Info() // No args
	logger.Close()

	content, _ := os.ReadFile(filepath.Join(tmpDir, "empty.log"))
	if len(content) == 0 {
		t.Error("Log file should not be empty")
	}
}

func TestLogger_SpecialCharacters(t *testing.T) {
	tmpDir := t.TempDir()
	//tmpDir, _ := os.Getwd()

	cfg := &LoggerConfig{
		Path:       tmpDir,
		Level:      LevelDebug,
		Stdout:     false,
		FileFormat: "special.log",
		QueueSize:  100,
	}

	logger, _ := NewLoggerWithConfig(cfg)
	logger.Info("hello\nworld")
	logger.Info("tab\there")
	logger.Info("中文日志")
	logger.Info("emoji 🎉")
	logger.Close()

	content, _ := os.ReadFile(filepath.Join(tmpDir, "special.log"))
	if !strings.Contains(string(content), "中文日志") {
		t.Error("Should contain Chinese characters")
	}
}

func TestLogger_LargeMessage(t *testing.T) {
	tmpDir := t.TempDir()
	//tmpDir, _ := os.Getwd()

	cfg := &LoggerConfig{
		Path:       tmpDir,
		Level:      LevelDebug,
		Stdout:     false,
		FileFormat: "large.log",
		QueueSize:  100,
	}

	logger, _ := NewLoggerWithConfig(cfg)

	// 1MB message
	largeMsg := strings.Repeat("x", 1024*1024)
	logger.Info(largeMsg)
	logger.Close()

	info, err := os.Stat(filepath.Join(tmpDir, "large.log"))
	if err != nil {
		t.Fatalf("Failed to stat log file: %v", err)
	}

	if info.Size() < 1024*1024 {
		t.Errorf("Log file too small: %d bytes", info.Size())
	}
}

// ============ Secure Random Tests | 安全随机数测试 ============

func TestSecureRandomInt(t *testing.T) {
	seen := make(map[int]bool)

	for i := 0; i < 100; i++ {
		n := secureRandomInt(1000000)
		if n < 0 || n >= 1000000 {
			t.Errorf("secureRandomInt returned out of range: %d", n)
		}
		seen[n] = true
	}

	// Should have some variety (very unlikely to get < 50 unique in 100 tries)
	if len(seen) < 50 {
		t.Errorf("secureRandomInt seems not random enough: only %d unique values", len(seen))
	}
}

// ============ Buffer Pool Tests | 缓冲池测试 ============

func TestBufferPool(t *testing.T) {
	buf1 := getBuf()
	buf1.WriteString("test")
	putBuf(buf1)

	buf2 := getBuf()
	if buf2.Len() != 0 {
		t.Error("Buffer from pool should be reset")
	}
	putBuf(buf2)
}

func BenchmarkBufferPool(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := getBuf()
			buf.WriteString("test message for buffer pool")
			putBuf(buf)
		}
	})
}

// ============ LogControl Interface Tests | 日志控制接口测试 ============

func TestLogger_ImplementsLogControl(t *testing.T) {
	cfg := &LoggerConfig{
		Stdout:     true,
		StdoutOnly: true,
		QueueSize:  DefaultQueueSize,
	}

	logger, _ := NewLoggerWithConfig(cfg)
	defer logger.Close()

	// Test all LogControl methods
	logger.SetLevel(LevelDebug)
	logger.SetPrefix("[TEST] ")
	logger.SetStdout(false)
	logger.Flush()

	path := logger.LogPath()
	if path != "" {
		t.Errorf("StdoutOnly mode should have empty LogPath, got %v", path)
	}

	dropCount := logger.DropCount()
	if dropCount != 0 {
		t.Errorf("Initial DropCount should be 0, got %v", dropCount)
	}
}

// ============ StdoutOnly Mode Tests | 仅控制台模式测试 ============

func TestLogger_StdoutOnlyMode(t *testing.T) {
	cfg := &LoggerConfig{
		Stdout:     true,
		StdoutOnly: true,
		Level:      LevelDebug,
		Prefix:     "[STDOUT-ONLY] ",
		QueueSize:  100,
	}

	logger, err := NewLoggerWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewLoggerWithConfig() error = %v", err)
	}
	defer logger.Close()

	// These should not panic and should output to stdout
	logger.Debug("stdout only debug")
	logger.Info("stdout only info")
	logger.Warn("stdout only warn")
	logger.Error("stdout only error")

	// Verify no file was created
	if logger.LogPath() != "" {
		t.Errorf("StdoutOnly mode should not have a log path")
	}
}

func TestLogger_StdoutOnlyWithStdoutDisabled(t *testing.T) {
	// Edge case: StdoutOnly=true but Stdout=false
	// prepareConfig should force Stdout=true
	cfg := &LoggerConfig{
		Stdout:     false, // Will be overridden
		StdoutOnly: true,
		QueueSize:  100,
	}

	logger, err := NewLoggerWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewLoggerWithConfig() error = %v", err)
	}
	defer logger.Close()

	currentCfg := logger.currentCfg()
	if !currentCfg.Stdout {
		t.Error("StdoutOnly mode should force Stdout=true")
	}
}
