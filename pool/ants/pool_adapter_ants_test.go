// @Author daixk 2025/12/26 10:00:00
package ants

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============ RenewPoolManager Tests | 续期池管理器测试 ============

func TestNewRenewPoolManagerWithDefaultConfig(t *testing.T) {
	mgr := NewRenewPoolManagerWithDefaultConfig()
	if mgr == nil {
		t.Fatal("NewRenewPoolManagerWithDefaultConfig returned nil")
	}
	defer mgr.Stop()

	if mgr.pool == nil {
		t.Error("pool should not be nil")
	}
	if mgr.config == nil {
		t.Error("config should not be nil")
	}
	if !mgr.started {
		t.Error("manager should be started")
	}
}

func TestNewRenewPoolManagerWithConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *RenewPoolConfig
		wantErr bool
	}{
		{
			name:    "nil config uses default",
			config:  nil,
			wantErr: false,
		},
		{
			name: "valid config",
			config: &RenewPoolConfig{
				MinSize:       50,
				MaxSize:       500,
				ScaleUpRate:   0.7,
				ScaleDownRate: 0.2,
				CheckInterval: 30 * time.Second,
				Expiry:        5 * time.Second,
				PreAlloc:      false,
				NonBlocking:   true,
			},
			wantErr: false,
		},
		{
			name: "MinSize <= 0 uses default",
			config: &RenewPoolConfig{
				MinSize:       0,
				MaxSize:       500,
				ScaleUpRate:   0.7,
				ScaleDownRate: 0.2,
				CheckInterval: 30 * time.Second,
				Expiry:        5 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "MaxSize < MinSize adjusts",
			config: &RenewPoolConfig{
				MinSize:       100,
				MaxSize:       50,
				ScaleUpRate:   0.7,
				ScaleDownRate: 0.2,
				CheckInterval: 30 * time.Second,
				Expiry:        5 * time.Second,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr, err := NewRenewPoolManagerWithConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRenewPoolManagerWithConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if mgr != nil {
				defer mgr.Stop()
				if mgr.pool == nil {
					t.Error("pool should not be nil")
				}
			}
		})
	}
}

func TestRenewPoolManager_Submit(t *testing.T) {
	mgr := NewRenewPoolManagerWithDefaultConfig()
	defer mgr.Stop()

	var counter int32
	var wg sync.WaitGroup

	taskCount := 10
	wg.Add(taskCount)

	for i := 0; i < taskCount; i++ {
		err := mgr.Submit(func() {
			atomic.AddInt32(&counter, 1)
			wg.Done()
		})
		if err != nil {
			t.Errorf("Submit() error = %v", err)
		}
	}

	wg.Wait()

	if atomic.LoadInt32(&counter) != int32(taskCount) {
		t.Errorf("expected counter = %d, got %d", taskCount, counter)
	}
}

func TestRenewPoolManager_Submit_AfterStop(t *testing.T) {
	mgr := NewRenewPoolManagerWithDefaultConfig()
	mgr.Stop()

	err := mgr.Submit(func() {})
	if err == nil {
		t.Error("Submit() should return error after Stop()")
	}
}

func TestRenewPoolManager_Stop(t *testing.T) {
	mgr := NewRenewPoolManagerWithDefaultConfig()

	// Stop should be idempotent | Stop 应该是幂等的
	mgr.Stop()
	mgr.Stop() // Should not panic | 不应该 panic

	if mgr.started {
		t.Error("manager should not be started after Stop()")
	}
}

func TestRenewPoolManager_Stats(t *testing.T) {
	mgr := NewRenewPoolManagerWithDefaultConfig()
	defer mgr.Stop()

	running, capacity, usage := mgr.Stats()

	if running < 0 {
		t.Errorf("running should be >= 0, got %d", running)
	}
	if capacity <= 0 {
		t.Errorf("capacity should be > 0, got %d", capacity)
	}
	if usage < 0 || usage > 1 {
		t.Errorf("usage should be between 0 and 1, got %f", usage)
	}
}

func TestRenewPoolManager_Stats_WithTasks(t *testing.T) {
	mgr := NewRenewPoolManagerWithDefaultConfig()
	defer mgr.Stop()

	// Submit some long-running tasks | 提交一些长时间运行的任务
	taskCount := 5
	doneCh := make(chan struct{})

	for i := 0; i < taskCount; i++ {
		_ = mgr.Submit(func() {
			<-doneCh // Wait for signal | 等待信号
		})
	}

	// Give some time for tasks to start | 等待任务启动
	time.Sleep(50 * time.Millisecond)

	running, capacity, usage := mgr.Stats()

	if running < taskCount {
		t.Errorf("expected running >= %d, got %d", taskCount, running)
	}
	if capacity < running {
		t.Errorf("capacity should be >= running, got capacity=%d, running=%d", capacity, running)
	}
	if usage <= 0 {
		t.Errorf("usage should be > 0 when tasks are running, got %f", usage)
	}

	close(doneCh) // Release tasks | 释放任务
}

func TestRenewPoolManager_AutoScale_ScaleUp(t *testing.T) {
	cfg := &RenewPoolConfig{
		MinSize:       10,
		MaxSize:       100,
		ScaleUpRate:   0.5, // Scale up when usage > 50% | 使用率超过 50% 时扩容
		ScaleDownRate: 0.1,
		CheckInterval: 50 * time.Millisecond, // Fast check for testing | 快速检查用于测试
		Expiry:        5 * time.Second,
		NonBlocking:   false, // Blocking mode to ensure tasks queue | 阻塞模式确保任务排队
	}

	mgr, err := NewRenewPoolManagerWithConfig(cfg)
	if err != nil {
		t.Fatalf("NewRenewPoolManagerWithConfig() error = %v", err)
	}
	defer mgr.Stop()

	_, initialCap, _ := mgr.Stats()

	// Submit many long-running tasks to trigger scale-up | 提交多个长时间运行的任务触发扩容
	doneCh := make(chan struct{})
	taskCount := initialCap + 5 // More than capacity | 超过容量

	for i := 0; i < taskCount; i++ {
		go func() {
			_ = mgr.Submit(func() {
				<-doneCh
			})
		}()
	}

	// Wait for auto-scale to trigger | 等待自动扩容触发
	time.Sleep(200 * time.Millisecond)

	_, newCap, _ := mgr.Stats()

	// Capacity should have increased or stayed at max | 容量应该增加或保持最大值
	if newCap < initialCap {
		t.Errorf("expected capacity to increase or stay same, initial=%d, new=%d", initialCap, newCap)
	}

	close(doneCh)
}

func TestRenewPoolManager_ConcurrentSubmit(t *testing.T) {
	mgr := NewRenewPoolManagerWithDefaultConfig()
	defer mgr.Stop()

	var counter int32
	var wg sync.WaitGroup

	goroutines := 100
	tasksPerGoroutine := 10

	wg.Add(goroutines * tasksPerGoroutine)

	for i := 0; i < goroutines; i++ {
		go func() {
			for j := 0; j < tasksPerGoroutine; j++ {
				err := mgr.Submit(func() {
					atomic.AddInt32(&counter, 1)
					wg.Done()
				})
				if err != nil {
					t.Errorf("Submit() error = %v", err)
					wg.Done()
				}
			}
		}()
	}

	wg.Wait()

	expected := int32(goroutines * tasksPerGoroutine)
	if atomic.LoadInt32(&counter) != expected {
		t.Errorf("expected counter = %d, got %d", expected, counter)
	}
}

// ============ RenewPoolConfig Tests | 续期池配置测试 ============

func TestDefaultRenewPoolConfig(t *testing.T) {
	cfg := DefaultRenewPoolConfig()

	if cfg.MinSize != DefaultMinSize {
		t.Errorf("MinSize = %d, want %d", cfg.MinSize, DefaultMinSize)
	}
	if cfg.MaxSize != DefaultMaxSize {
		t.Errorf("MaxSize = %d, want %d", cfg.MaxSize, DefaultMaxSize)
	}
	if cfg.ScaleUpRate != DefaultScaleUpRate {
		t.Errorf("ScaleUpRate = %f, want %f", cfg.ScaleUpRate, DefaultScaleUpRate)
	}
	if cfg.ScaleDownRate != DefaultScaleDownRate {
		t.Errorf("ScaleDownRate = %f, want %f", cfg.ScaleDownRate, DefaultScaleDownRate)
	}
	if cfg.CheckInterval != DefaultCheckInterval {
		t.Errorf("CheckInterval = %v, want %v", cfg.CheckInterval, DefaultCheckInterval)
	}
	if cfg.Expiry != DefaultExpiry {
		t.Errorf("Expiry = %v, want %v", cfg.Expiry, DefaultExpiry)
	}
	if cfg.PreAlloc != false {
		t.Errorf("PreAlloc = %v, want false", cfg.PreAlloc)
	}
	if cfg.NonBlocking != true {
		t.Errorf("NonBlocking = %v, want true", cfg.NonBlocking)
	}
}

func TestRenewPoolConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *RenewPoolConfig
		wantErr bool
	}{
		{
			name:    "nil config is valid",
			config:  nil,
			wantErr: false,
		},
		{
			name:    "default config is valid",
			config:  DefaultRenewPoolConfig(),
			wantErr: false,
		},
		{
			name: "MinSize <= 0 is invalid",
			config: &RenewPoolConfig{
				MinSize:       0,
				MaxSize:       100,
				ScaleUpRate:   0.8,
				ScaleDownRate: 0.3,
				CheckInterval: time.Minute,
				Expiry:        10 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "MaxSize < MinSize is invalid",
			config: &RenewPoolConfig{
				MinSize:       100,
				MaxSize:       50,
				ScaleUpRate:   0.8,
				ScaleDownRate: 0.3,
				CheckInterval: time.Minute,
				Expiry:        10 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "ScaleUpRate <= 0 is invalid",
			config: &RenewPoolConfig{
				MinSize:       100,
				MaxSize:       200,
				ScaleUpRate:   0,
				ScaleDownRate: 0.3,
				CheckInterval: time.Minute,
				Expiry:        10 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "ScaleUpRate > 1 is invalid",
			config: &RenewPoolConfig{
				MinSize:       100,
				MaxSize:       200,
				ScaleUpRate:   1.5,
				ScaleDownRate: 0.3,
				CheckInterval: time.Minute,
				Expiry:        10 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "ScaleDownRate < 0 is invalid",
			config: &RenewPoolConfig{
				MinSize:       100,
				MaxSize:       200,
				ScaleUpRate:   0.8,
				ScaleDownRate: -0.1,
				CheckInterval: time.Minute,
				Expiry:        10 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "ScaleDownRate > 1 is invalid",
			config: &RenewPoolConfig{
				MinSize:       100,
				MaxSize:       200,
				ScaleUpRate:   0.8,
				ScaleDownRate: 1.5,
				CheckInterval: time.Minute,
				Expiry:        10 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "CheckInterval <= 0 is invalid",
			config: &RenewPoolConfig{
				MinSize:       100,
				MaxSize:       200,
				ScaleUpRate:   0.8,
				ScaleDownRate: 0.3,
				CheckInterval: 0,
				Expiry:        10 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "Expiry <= 0 is invalid",
			config: &RenewPoolConfig{
				MinSize:       100,
				MaxSize:       200,
				ScaleUpRate:   0.8,
				ScaleDownRate: 0.3,
				CheckInterval: time.Minute,
				Expiry:        0,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRenewPoolConfig_Clone(t *testing.T) {
	original := &RenewPoolConfig{
		MinSize:       50,
		MaxSize:       500,
		ScaleUpRate:   0.7,
		ScaleDownRate: 0.2,
		CheckInterval: 30 * time.Second,
		Expiry:        5 * time.Second,
		PreAlloc:      true,
		NonBlocking:   false,
	}

	cloned := original.Clone()

	if cloned == original {
		t.Error("Clone() should return a different pointer")
	}
	if cloned.MinSize != original.MinSize {
		t.Errorf("MinSize mismatch: got %d, want %d", cloned.MinSize, original.MinSize)
	}
	if cloned.MaxSize != original.MaxSize {
		t.Errorf("MaxSize mismatch: got %d, want %d", cloned.MaxSize, original.MaxSize)
	}
	if cloned.ScaleUpRate != original.ScaleUpRate {
		t.Errorf("ScaleUpRate mismatch: got %f, want %f", cloned.ScaleUpRate, original.ScaleUpRate)
	}
	if cloned.ScaleDownRate != original.ScaleDownRate {
		t.Errorf("ScaleDownRate mismatch: got %f, want %f", cloned.ScaleDownRate, original.ScaleDownRate)
	}
	if cloned.CheckInterval != original.CheckInterval {
		t.Errorf("CheckInterval mismatch: got %v, want %v", cloned.CheckInterval, original.CheckInterval)
	}
	if cloned.Expiry != original.Expiry {
		t.Errorf("Expiry mismatch: got %v, want %v", cloned.Expiry, original.Expiry)
	}
	if cloned.PreAlloc != original.PreAlloc {
		t.Errorf("PreAlloc mismatch: got %v, want %v", cloned.PreAlloc, original.PreAlloc)
	}
	if cloned.NonBlocking != original.NonBlocking {
		t.Errorf("NonBlocking mismatch: got %v, want %v", cloned.NonBlocking, original.NonBlocking)
	}

	// Modify clone should not affect original | 修改克隆不应影响原始
	cloned.MinSize = 999
	if original.MinSize == 999 {
		t.Error("Modifying clone affected original")
	}
}

func TestRenewPoolConfig_Clone_Nil(t *testing.T) {
	var cfg *RenewPoolConfig
	cloned := cfg.Clone()
	if cloned != nil {
		t.Error("Clone() of nil should return nil")
	}
}

func TestRenewPoolConfig_Setters(t *testing.T) {
	cfg := &RenewPoolConfig{}

	// Test chaining | 测试链式调用
	result := cfg.
		SetMinSize(50).
		SetMaxSize(500).
		SetScaleUpRate(0.75).
		SetScaleDownRate(0.25).
		SetCheckInterval(45 * time.Second).
		SetExpiry(15 * time.Second).
		SetPrintStatusInterval(5 * time.Minute).
		SetPreAlloc(true).
		SetNonBlocking(false)

	if result != cfg {
		t.Error("Setters should return the same config pointer for chaining")
	}

	if cfg.MinSize != 50 {
		t.Errorf("MinSize = %d, want 50", cfg.MinSize)
	}
	if cfg.MaxSize != 500 {
		t.Errorf("MaxSize = %d, want 500", cfg.MaxSize)
	}
	if cfg.ScaleUpRate != 0.75 {
		t.Errorf("ScaleUpRate = %f, want 0.75", cfg.ScaleUpRate)
	}
	if cfg.ScaleDownRate != 0.25 {
		t.Errorf("ScaleDownRate = %f, want 0.25", cfg.ScaleDownRate)
	}
	if cfg.CheckInterval != 45*time.Second {
		t.Errorf("CheckInterval = %v, want 45s", cfg.CheckInterval)
	}
	if cfg.Expiry != 15*time.Second {
		t.Errorf("Expiry = %v, want 15s", cfg.Expiry)
	}
	if cfg.PrintStatusInterval != 5*time.Minute {
		t.Errorf("PrintStatusInterval = %v, want 5m", cfg.PrintStatusInterval)
	}
	if cfg.PreAlloc != true {
		t.Errorf("PreAlloc = %v, want true", cfg.PreAlloc)
	}
	if cfg.NonBlocking != false {
		t.Errorf("NonBlocking = %v, want false", cfg.NonBlocking)
	}
}

// ============ Benchmark Tests | 基准测试 ============

func BenchmarkRenewPoolManager_Submit(b *testing.B) {
	mgr := NewRenewPoolManagerWithDefaultConfig()
	defer mgr.Stop()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mgr.Submit(func() {
			// Empty task | 空任务
		})
	}
}

func BenchmarkRenewPoolManager_Submit_WithWork(b *testing.B) {
	mgr := NewRenewPoolManagerWithDefaultConfig()
	defer mgr.Stop()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mgr.Submit(func() {
			// Simulate some work | 模拟一些工作
			time.Sleep(time.Microsecond)
		})
	}
}

func BenchmarkRenewPoolManager_Stats(b *testing.B) {
	mgr := NewRenewPoolManagerWithDefaultConfig()
	defer mgr.Stop()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mgr.Stats()
	}
}

func BenchmarkRenewPoolManager_ConcurrentSubmit(b *testing.B) {
	mgr := NewRenewPoolManagerWithDefaultConfig()
	defer mgr.Stop()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = mgr.Submit(func() {
				// Empty task | 空任务
			})
		}
	})
}

// ============ Auto-Scale Demo Test | 自动扩缩容演示测试 ============

// TestRenewPoolManager_AutoScale_Demo demonstrates the auto-scaling behavior with status printing
// 演示自动扩缩容行为并打印状态
// Run with: go test -v -run TestRenewPoolManager_AutoScale_Demo -timeout 60s
func TestRenewPoolManager_AutoScale_Demo(t *testing.T) {
	cfg := &RenewPoolConfig{
		MinSize:       5,                      // Minimum pool size | 最小池大小
		MaxSize:       50,                     // Maximum pool size | 最大池大小
		ScaleUpRate:   0.6,                    // Scale up when usage > 60% | 使用率超过 60% 时扩容
		ScaleDownRate: 0.2,                    // Scale down when usage < 20% | 使用率低于 20% 时缩容
		CheckInterval: 200 * time.Millisecond, // Check every 200ms | 每 200ms 检查一次
		Expiry:        2 * time.Second,        // Worker expiry | Worker 过期时间
		NonBlocking:   false,                  // Blocking mode | 阻塞模式
	}

	mgr, err := NewRenewPoolManagerWithConfig(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool manager: %v", err)
	}
	defer mgr.Stop()

	// Status printer | 状态打印器
	stopPrinter := make(chan struct{})
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		lastCap := 0
		for {
			select {
			case <-ticker.C:
				running, capacity, usage := mgr.Stats()
				action := "  STABLE  "
				if capacity > lastCap {
					action = "⬆️ SCALE UP"
				} else if capacity < lastCap {
					action = "⬇️ SCALE DN"
				}
				lastCap = capacity

				// Print status bar | 打印状态条
				usageBar := generateUsageBar(usage, 20)
				t.Logf("[%s] Cap: %3d | Running: %3d | Usage: %5.1f%% |%s|",
					action, capacity, running, usage*100, usageBar)

			case <-stopPrinter:
				return
			}
		}
	}()

	t.Log("========== Phase 1: Initial State (2s) | 初始状态 ==========")
	time.Sleep(2 * time.Second)

	t.Log("========== Phase 2: High Load - Triggering Scale Up | 高负载 - 触发扩容 ==========")
	// Submit many long-running tasks | 提交大量长时间运行的任务
	phase2Done := make(chan struct{})
	taskCount := 30
	for i := 0; i < taskCount; i++ {
		go func(id int) {
			_ = mgr.Submit(func() {
				<-phase2Done // Wait for signal | 等待信号
			})
		}(i)
	}
	time.Sleep(3 * time.Second) // Wait for scale up | 等待扩容

	t.Log("========== Phase 3: Releasing Tasks - Observe Scale Down | 释放任务 - 观察缩容 ==========")
	close(phase2Done)           // Release all tasks | 释放所有任务
	time.Sleep(4 * time.Second) // Wait for scale down | 等待缩容

	t.Log("========== Phase 4: Burst Load Again | 再次突发负载 ==========")
	phase4Done := make(chan struct{})
	for i := 0; i < 40; i++ {
		go func(id int) {
			_ = mgr.Submit(func() {
				<-phase4Done
			})
		}(i)
	}
	time.Sleep(3 * time.Second)

	t.Log("========== Phase 5: Gradual Release | 逐步释放 ==========")
	close(phase4Done)
	time.Sleep(4 * time.Second)

	t.Log("========== Phase 6: Final State | 最终状态 ==========")
	time.Sleep(2 * time.Second)

	close(stopPrinter)

	// Final stats | 最终统计
	running, capacity, usage := mgr.Stats()
	t.Logf("Final Stats - Capacity: %d, Running: %d, Usage: %.1f%%", capacity, running, usage*100)
}

// generateUsageBar creates a visual usage bar | 生成可视化使用率条
func generateUsageBar(usage float64, width int) string {
	filled := int(usage * float64(width))
	if filled > width {
		filled = width
	}

	bar := make([]byte, width)
	for i := 0; i < width; i++ {
		if i < filled {
			bar[i] = '#'
		} else {
			bar[i] = '-'
		}
	}
	return string(bar)
}

// TestRenewPoolManager_AutoScale_StressTest stress test for auto-scaling
// 自动扩缩容压力测试
func TestRenewPoolManager_AutoScale_StressTest(t *testing.T) {
	cfg := &RenewPoolConfig{
		MinSize:       10,
		MaxSize:       100,
		ScaleUpRate:   0.7,
		ScaleDownRate: 0.2,
		CheckInterval: 100 * time.Millisecond,
		Expiry:        1 * time.Second,
		NonBlocking:   false,
	}

	mgr, err := NewRenewPoolManagerWithConfig(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool manager: %v", err)
	}
	defer mgr.Stop()

	// Track capacity changes | 记录容量变化
	var (
		maxCapSeen = 0
		minCapSeen = 1000
		scaleUps   = 0
		scaleDowns = 0
		lastCap    = cfg.MinSize
	)

	stopMonitor := make(chan struct{})
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				_, capacity, _ := mgr.Stats()
				if capacity > maxCapSeen {
					maxCapSeen = capacity
				}
				if capacity < minCapSeen {
					minCapSeen = capacity
				}
				if capacity > lastCap {
					scaleUps++
				} else if capacity < lastCap {
					scaleDowns++
				}
				lastCap = capacity
			case <-stopMonitor:
				return
			}
		}
	}()

	// Wave pattern load | 波浪模式负载
	for wave := 0; wave < 3; wave++ {
		t.Logf("Wave %d: Increasing load...", wave+1)
		doneCh := make(chan struct{})

		// Increase load | 增加负载
		for i := 0; i < 50+wave*20; i++ {
			go func() {
				_ = mgr.Submit(func() {
					<-doneCh
				})
			}()
		}
		time.Sleep(1500 * time.Millisecond)

		t.Logf("Wave %d: Releasing load...", wave+1)
		close(doneCh)
		time.Sleep(2 * time.Second)
	}

	close(stopMonitor)

	t.Logf("Stress Test Results:")
	t.Logf("  - Max capacity seen: %d", maxCapSeen)
	t.Logf("  - Min capacity seen: %d", minCapSeen)
	t.Logf("  - Scale up events: %d", scaleUps)
	t.Logf("  - Scale down events: %d", scaleDowns)

	// Verify scaling occurred | 验证发生了扩缩容
	if scaleUps == 0 {
		t.Error("Expected at least one scale up event")
	}
	if scaleDowns == 0 {
		t.Error("Expected at least one scale down event")
	}
	if maxCapSeen <= cfg.MinSize {
		t.Errorf("Expected max capacity > MinSize(%d), got %d", cfg.MinSize, maxCapSeen)
	}
}
