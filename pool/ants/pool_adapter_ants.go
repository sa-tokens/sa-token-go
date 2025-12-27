// @Author daixk 2025/12/12 11:55:00
package ants

import (
	"fmt"
	"sync"
	"time"

	"github.com/panjf2000/ants/v2"
)

// RenewPoolManager manages a dynamic scaling goroutine pool for token renewal tasks | 续期任务协程池管理器
type RenewPoolManager struct {
	pool      *ants.Pool       // ants pool instance | ants 协程池实例
	config    *RenewPoolConfig // Configuration object | 池配置对象
	mu        sync.Mutex       // Synchronization lock | 互斥锁
	stopCh    chan struct{}    // Stop signal channel | 停止信号通道
	started   bool             // Indicates if pool manager is running | 是否已启动
	closeOnce sync.Once        // Ensure Stop only executes once | 确保 Stop 只执行一次
}

// NewRenewPoolManagerWithDefaultConfig creates manager with default config | 使用默认配置创建续期池管理器
func NewRenewPoolManagerWithDefaultConfig() *RenewPoolManager {
	mgr := &RenewPoolManager{
		config:  DefaultRenewPoolConfig(),
		stopCh:  make(chan struct{}),
		started: true,
	}

	_ = mgr.initPool()

	// Start auto-scaling routine | 启动自动扩缩容协程
	go mgr.autoScale()

	return mgr
}

// NewRenewPoolManagerWithConfig creates manager with config | 使用配置创建续期池管理器
func NewRenewPoolManagerWithConfig(cfg *RenewPoolConfig) (*RenewPoolManager, error) {
	if cfg == nil {
		cfg = DefaultRenewPoolConfig()
	}
	if cfg.MinSize <= 0 {
		cfg.MinSize = DefaultMinSize
	}
	if cfg.MaxSize < cfg.MinSize {
		cfg.MaxSize = cfg.MinSize
	}

	mgr := &RenewPoolManager{
		config:  cfg,
		stopCh:  make(chan struct{}),
		started: true,
	}

	if err := mgr.initPool(); err != nil {
		return nil, err
	}

	// Start auto-scaling routine | 启动自动扩缩容协程
	go mgr.autoScale()

	return mgr, nil
}

// initPool initializes the ants pool | 初始化 ants 协程池
func (m *RenewPoolManager) initPool() error {
	p, err := ants.NewPool(
		m.config.MinSize,
		ants.WithExpiryDuration(m.config.Expiry),
		ants.WithPreAlloc(m.config.PreAlloc),
		ants.WithNonblocking(m.config.NonBlocking),
	)
	if err != nil {
		return err
	}

	m.pool = p
	return nil
}

// Submit submits a renewal task | 提交续期任务
func (m *RenewPoolManager) Submit(task func()) error {
	if !m.started {
		return fmt.Errorf("renew pool not started")
	}
	return m.pool.Submit(task)
}

// Stop stops the auto-scaling process | 停止自动扩缩容
func (m *RenewPoolManager) Stop() {
	m.closeOnce.Do(func() {
		if !m.started {
			return
		}
		close(m.stopCh)
		m.started = false

		if m.pool != nil && !m.pool.IsClosed() {
			_ = m.pool.ReleaseTimeout(3 * time.Second)
		}
	})
}

// Stats returns current pool statistics | 返回当前池状态
func (m *RenewPoolManager) Stats() (running, capacity int, usage float64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	running = m.pool.Running() // Active tasks | 当前运行任务数
	capacity = m.pool.Cap()    // Pool capacity | 当前池容量
	if capacity > 0 {
		usage = float64(running) / float64(capacity) // Usage ratio | 当前使用率
		// Cap usage at 1.0 to handle race condition between Running() and Cap() calls
		// 限制使用率最大为 1.0，处理 Running() 和 Cap() 调用之间的竞态条件
		if usage > 1.0 {
			usage = 1.0
		}
	}

	return
}

// autoScale automatic pool scale-up/down logic | 自动扩缩容逻辑
func (m *RenewPoolManager) autoScale() {
	ticker := time.NewTicker(m.config.CheckInterval) // Ticker for periodic usage checks | 定时器，用于定期检测使用率
	defer ticker.Stop()                              // Stop ticker on exit | 函数退出时停止定时器

	for {
		select {
		case <-ticker.C:
			m.mu.Lock() // Protect concurrent access | 加锁防止并发冲突

			// Get current pool stats | 获取当前运行状态
			running := m.pool.Running() // Number of active goroutines | 当前正在执行的任务数
			capacity := m.pool.Cap()    // Current pool capacity | 当前协程池容量

			// Skip if capacity is 0 to avoid division by zero | 容量为0时跳过，避免除零
			if capacity <= 0 {
				m.mu.Unlock()
				continue
			}

			usage := float64(running) / float64(capacity) // Current usage ratio | 当前使用率（运行数 ÷ 总容量）

			switch {
			// Expand if usage exceeds threshold and capacity < MaxSize | 当使用率超过扩容阈值且容量小于最大值时扩容
			case usage > m.config.ScaleUpRate && capacity < m.config.MaxSize:
				newCap := int(float64(capacity) * 1.5) // Increase capacity by 1.5x | 扩容为当前的 1.5 倍
				if newCap > m.config.MaxSize {         // Cap to maximum size | 限制最大值
					newCap = m.config.MaxSize
				}
				m.pool.Tune(newCap) // Apply new pool capacity | 调整 ants 池容量

			// Reduce if usage below threshold and capacity > MinSize | 当使用率低于缩容阈值且容量大于最小值时缩容
			case usage < m.config.ScaleDownRate && capacity > m.config.MinSize:
				newCap := int(float64(capacity) * 0.7) // Reduce capacity to 70% | 缩容为当前的 70%
				if newCap < m.config.MinSize {         // Ensure not below MinSize | 限制最小值
					newCap = m.config.MinSize
				}
				m.pool.Tune(newCap) // Apply new pool capacity | 调整 ants 池容量
			}

			m.mu.Unlock() // Unlock after adjustment | 解锁

		case <-m.stopCh:
			// Stop signal received, exit loop | 收到停止信号，终止扩缩容协程
			return
		}
	}
}
