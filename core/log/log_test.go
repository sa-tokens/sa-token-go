package log

import (
	"context"
	"fmt"
	"github.com/gogf/gf/v2/os/glog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestAllLevelsAndRotation 测试所有日志级别与切分逻辑 | Test all log levels and rotation
func TestAllLevelsAndRotation(t *testing.T) {
	logger, err := NewBuilder().
		//Prefix("[TEST] ").
		Level(LevelDebug).
		Stdout(true).
		RotateSize(2 * 1024).          // 超过2KB切分 | rotate every 2KB
		RotateExpire(2 * time.Second). // 每2秒自动切分 | rotate every 2s
		RotateBackupLimit(3).          // 保留3个文件 | keep 3 backups
		RotateBackupDays(1).           // 保留1天 | keep 1 day
		Build()
	if err != nil {
		t.Fatalf("failed to build logger: %v", err)
	}
	defer logger.Close()

	logger.Print("Print level message")
	logger.Printf("Printf formatted %s", "message")

	logger.Debug("Debug message")
	logger.Debugf("Debugf formatted %s", "debugging")

	logger.Info("Info message")
	logger.Infof("Infof formatted %s", "information")

	logger.Warn("Warning message")
	logger.Warnf("Warningf formatted %s", "warning")

	logger.Error("Error message")
	logger.Errorf("Errorf formatted %s", "error")

	t.Log("all log levels written successfully")

	for i := 0; i < 300; i++ {
		switch i % 4 {
		case 0:
			logger.Debugf("Rotation Debug line %d", i)
		case 1:
			logger.Infof("Rotation Info line %d", i)
		case 2:
			logger.Warnf("Rotation Warning line %d", i)
		default:
			logger.Errorf("Rotation Error line %d", i)
		}
		time.Sleep(50 * time.Millisecond)
	}

	time.Sleep(4 * time.Second)

	files, _ := filepath.Glob(filepath.Join(logger.LogPath(), "*.log"))
	if len(files) == 0 {
		t.Fatal("no log files generated")
	}
	t.Logf("%d log files generated under: %s", len(files), logger.LogPath())
	for _, f := range files {
		info, _ := os.Stat(f)
		t.Logf(" - %s (%d bytes)", filepath.Base(f), info.Size())
	}
}

// BenchmarkSaTokenLogger_Sequential 顺序写入性能测试 | Sequential benchmark
func BenchmarkSaTokenLogger_Sequential(b *testing.B) {
	dir := filepath.Join(getProjectDir(), "bench_sa_seq")
	_ = os.MkdirAll(dir, 0755)

	logger, _ := NewBuilder().
		Path(dir).
		Stdout(false).
		RotateSize(0).
		Build()
	defer logger.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Infof("sequential benchmark log line %d", i)
	}
	b.StopTimer()
}

// BenchmarkSaTokenLogger_Parallel 并发写入性能测试 | Parallel benchmark
func BenchmarkSaTokenLogger_Parallel(b *testing.B) {
	dir := filepath.Join(getProjectDir(), "bench_sa_parallel")
	_ = os.MkdirAll(dir, 0755)

	logger, _ := NewBuilder().
		Path(dir).
		Stdout(false).
		RotateSize(0).
		Build()
	defer logger.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			logger.Infof("parallel benchmark log line %d", i)
			i++
		}
	})
	b.StopTimer()
}

// BenchmarkGfLogger_Sequential GoFrame glog 顺序写入 | GF sequential benchmark
func BenchmarkGfLogger_Sequential(b *testing.B) {
	dir := filepath.Join(getProjectDir(), "bench_gf_seq")
	_ = os.MkdirAll(dir, 0755)

	logger := glog.New()
	logger.SetStdoutPrint(false)
	logger.SetPath(dir)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Infof(context.Background(), "gflog sequential line %d", i)
	}
	b.StopTimer()
}

// BenchmarkGfLogger_Parallel GoFrame glog 并发写入 | GF parallel benchmark
func BenchmarkGfLogger_Parallel(b *testing.B) {
	dir := filepath.Join(getProjectDir(), "bench_gf_parallel")
	_ = os.MkdirAll(dir, 0755)

	logger := glog.New()
	logger.SetStdoutPrint(false)
	logger.SetPath(dir)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			logger.Infof(context.Background(), "gflog parallel line %d", i)
			i++
		}
	})
	b.StopTimer()
}

// TestSummary 输出运行方式 | Print run commands
func TestSummary(t *testing.T) {
	fmt.Println("run test: go test -v ./core/log")
	fmt.Println("run benchmark: go test -bench=. -benchmem ./core/log")
}

// getProjectDir 获取当前项目根目录 | Get project root path
func getProjectDir() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	return wd
}
