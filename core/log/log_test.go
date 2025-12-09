// @Author daixk 2025/12/6 17:13:00
package log

//import (
//	"os"
//	"path/filepath"
//	"strings"
//	"sync"
//	"testing"
//	"time"
//)
//
//// ---------------- Configuration Tests ----------------
//
//func TestLoggerBuilderAndConfig(t *testing.T) {
//	b := NewBuilder().
//		Path("test_logs").
//		FileFormat("custom_{Y}-{m}-{d}.log").
//		Prefix("[TEST] ").
//		Level(LevelDebug).
//		TimeFormat("2006-01-02 15:04:05").
//		Stdout(false).
//		RotateSize(1024).
//		RotateExpire(time.Hour).
//		RotateBackupLimit(3).
//		RotateBackupDays(1)
//
//	logger, err := b.Build()
//	if err != nil {
//		t.Fatalf("Build() failed: %v", err)
//	}
//	defer logger.Close()
//
//	cfg := logger.currentCfg()
//
//	if cfg.Level != LevelDebug {
//		t.Errorf("expected LevelDebug, got %v", cfg.Level)
//	}
//	if !strings.Contains(cfg.FileFormat, "custom_") {
//		t.Errorf("FileFormat not set correctly")
//	}
//	if !strings.Contains(cfg.Prefix, "[TEST]") {
//		t.Errorf("Prefix not set correctly")
//	}
//
//	path := ensureDefaultPath(&cfg)
//	if path == "" {
//		t.Errorf("ensureDefaultPath returned empty path")
//	}
//}
//
//// ---------------- Log Output Tests ----------------
//
//func TestLoggerOutputToFileAndStdout(t *testing.T) {
//	dir, _ := os.Getwd()
//
//	logger, err := NewBuilder().
//		Path(dir).
//		Prefix("[OUT] ").
//		Stdout(true).
//		Level(LevelDebug).
//		Build()
//	if err != nil {
//		t.Fatalf("Build() failed: %v", err)
//	}
//	defer logger.Close()
//
//	// 写日志
//	logger.Info("File log test line 1")
//	logger.Debugf("File log formatted: %d", 123)
//	logger.Warn("File log test line 2")
//
//	// 等待异步写入完成
//	time.Sleep(200 * time.Millisecond)
//	logger.Flush()
//
//	files, err := filepath.Glob(filepath.Join(dir, "*.log"))
//	if err != nil || len(files) == 0 {
//		t.Fatalf("expected at least one log file, got none: %v", err)
//	}
//
//	data, err := os.ReadFile(files[0])
//	if err != nil {
//		t.Fatalf("failed to read log file: %v", err)
//	}
//
//	content := string(data)
//	if !strings.Contains(content, "[OUT]") {
//		t.Errorf("log file missing prefix: %s", content)
//	}
//	if !strings.Contains(content, "File log test line 1") {
//		t.Errorf("log file missing expected content")
//	}
//}
//
//// ---------------- Rotation Tests ----------------
//
//func TestLoggerRotationBySize(t *testing.T) {
//	dir, _ := os.Getwd()
//
//	logger, err := NewBuilder().
//		Path(dir).
//		Prefix("[ROTATE] ").
//		RotateSize(512).
//		Level(LevelInfo).
//		Stdout(false).
//		RotateBackupLimit(5).
//		Build()
//	if err != nil {
//		t.Fatalf("Build() failed: %v", err)
//	}
//	defer logger.Close()
//
//	// 连续写日志以触发切分
//	for i := 0; i < 200; i++ {
//		logger.Infof("Rotating log line %03d - this should create multiple files", i)
//	}
//	time.Sleep(300 * time.Millisecond)
//	logger.Flush()
//
//	files, err := filepath.Glob(filepath.Join(dir, "*.log"))
//	if err != nil {
//		t.Fatalf("glob failed: %v", err)
//	}
//	if len(files) < 1 {
//		t.Errorf("expected rotated files, got: %v", files)
//	}
//}
//
//// ---------------- Global Logger Tests ----------------
//
//func TestGlobalLogger(t *testing.T) {
//	dir, _ := os.Getwd()
//
//	l, err := NewBuilder().
//		Path(dir).
//		Prefix("[GLOBAL] ").
//		Build()
//	if err != nil {
//		t.Fatalf("Build() failed: %v", err)
//	}
//	defer l.Close()
//
//	SetGlobalLogger(l)
//	Info("Global logger test 1")
//	Infof("Global formatted: %d", 999)
//
//	time.Sleep(100 * time.Millisecond)
//	l.Flush()
//
//	files, _ := filepath.Glob(filepath.Join(dir, "*.log"))
//	if len(files) == 0 {
//		t.Fatal("expected global logger to write to file")
//	}
//
//	data, _ := os.ReadFile(files[0])
//	if !strings.Contains(string(data), "Global logger test 1") {
//		t.Errorf("global logger output not found")
//	}
//}
//
//// ---------------- NopLogger Tests ----------------
//
//func TestNopLoggerNoOutput(t *testing.T) {
//	n := &NopLogger{}
//	n.Info("should not appear")
//	n.Debugf("format %d", 42)
//
//	// nothing to assert except no panic
//}
//
//// ---------------- Concurrency Tests ----------------
//
//func TestConcurrentLogging(t *testing.T) {
//	dir, _ := os.Getwd()
//	logger, err := NewBuilder().
//		Path(dir).
//		Prefix("[CONCURRENT] ").
//		Build()
//	if err != nil {
//		t.Fatalf("Build() failed: %v", err)
//	}
//	defer logger.Close()
//
//	var wg sync.WaitGroup
//	for i := 0; i < 50; i++ {
//		wg.Add(1)
//		go func(id int) {
//			defer wg.Done()
//			for j := 0; j < 100; j++ {
//				logger.Infof("goroutine=%d line=%d", id, j)
//			}
//		}(i)
//	}
//	wg.Wait()
//	logger.Flush()
//
//	files, _ := filepath.Glob(filepath.Join(dir, "*.log"))
//	if len(files) == 0 {
//		t.Fatal("no log files created under concurrent writes")
//	}
//}
//
//// ---------------- Benchmark Tests ----------------
//
//func BenchmarkLogger_Info(b *testing.B) {
//	dir, _ := os.Getwd()
//	logger, _ := NewBuilder().
//		Path(dir).
//		Prefix("[BENCH] ").
//		Stdout(false).
//		Build()
//	defer logger.Close()
//
//	b.ResetTimer()
//	for i := 0; i < b.N; i++ {
//		logger.Info("benchmark log line", i)
//	}
//}
//
//func BenchmarkLogger_Concurrent(b *testing.B) {
//	dir, _ := os.Getwd()
//	logger, _ := NewBuilder().
//		Path(dir).
//		Prefix("[BENCH-CONCURRENT] ").
//		Stdout(false).
//		Build()
//	defer logger.Close()
//
//	b.ResetTimer()
//	b.RunParallel(func(pb *testing.PB) {
//		for pb.Next() {
//			logger.Infof("parallel log line %d", time.Now().UnixNano())
//		}
//	})
//}
//
//func BenchmarkNopLogger(b *testing.B) {
//	n := &NopLogger{}
//	b.ResetTimer()
//	for i := 0; i < b.N; i++ {
//		n.Info("nop log test")
//	}
//}
//
//func BenchmarkGlobalLogger(b *testing.B) {
//	dir, _ := os.Getwd()
//	l, _ := NewBuilder().Path(dir).Stdout(false).Build()
//	SetGlobalLogger(l)
//	defer l.Close()
//
//	b.ResetTimer()
//	for i := 0; i < b.N; i++ {
//		Infof("benchmark global log line %d", i)
//	}
//}
//
//// ---------------- Performance Comparison: Zap & GoFrame ----------------
//
////// BenchmarkZapLogger compares zap performance with our logger | 对比 zap 日志性能
////func BenchmarkZapLogger(b *testing.B) {
////	dir, _ := os.Getwd()
////	logPath := filepath.Join(dir, "zap_bench.log")
////
////	cfg := zap.NewProductionConfig()
////	cfg.OutputPaths = []string{logPath}
////	zapLogger, err := cfg.Build()
////	if err != nil {
////		b.Fatalf("failed to create zap logger: %v", err)
////	}
////	defer zapLogger.Sync()
////
////	b.ResetTimer()
////	for i := 0; i < b.N; i++ {
////		zapLogger.Info("zap benchmark log", zap.Int("index", i))
////	}
////}
////
////// BenchmarkGFLogger compares GoFrame glog performance with our logger | 对比 GoFrame 日志性能
////func BenchmarkGFLogger(b *testing.B) {
////	ctx := context.Background()
////	dir, _ := os.Getwd()
////
////	logger := glog.New()
////	logger.SetPath(dir)
////	logger.SetFile("gf_bench.log")
////	logger.SetStdoutPrint(false)
////	logger.SetAsync(true) // 为公平起见，关闭异步写入
////
////	b.ResetTimer()
////	for i := 0; i < b.N; i++ {
////		logger.Info(ctx, "gf benchmark log", i)
////	}
////}
////
////// BenchmarkOurLogger compares our logger performance | 对比自研日志性能
////func BenchmarkOurLogger(b *testing.B) {
////	dir, _ := os.Getwd()
////	logger, err := NewBuilder().
////		Path(dir).
////		Prefix("[OUR] ").
////		Stdout(false).
////		Build()
////	if err != nil {
////		b.Fatalf("failed to create our logger: %v", err)
////	}
////	defer logger.Close()
////
////	b.ResetTimer()
////	for i := 0; i < b.N; i++ {
////		logger.Info("our benchmark log", i)
////	}
////}
