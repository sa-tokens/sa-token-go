// @Author daixk 2025-10-28 22:00:20
package pool

import (
	"github.com/click33/sa-token-go/core/config"
	"github.com/click33/sa-token-go/core/dep"
	"github.com/click33/sa-token-go/core/log"
	"github.com/click33/sa-token-go/core/serror"
	"sync"
	"time"

	"github.com/panjf2000/ants/v2"
)

// Default configuration constants | 默认配置常量
const (
	DefaultMinSize       = 100              // Minimum pool size | 最小协程数
	DefaultMaxSize       = 2000             // Maximum pool size | 最大协程数
	DefaultScaleUpRate   = 0.8              // Scale-up threshold (expand when usage exceeds this ratio) | 扩容阈值，当使用率超过此比例时扩容
	DefaultScaleDownRate = 0.3              // Scale-down threshold (shrink when usage below this ratio) | 缩容阈值，当使用率低于此比例时缩容
	DefaultCheckInterval = time.Minute      // Interval for auto-scaling checks | 检查间隔
	DefaultExpiry        = 10 * time.Second // Idle worker expiry duration | 空闲协程过期时间
)

// RenewPoolConfig configuration for the renewal pool manager | 续期池配置
type RenewPoolConfig struct {
	MinSize             int           // Minimum pool size | 最小协程数
	MaxSize             int           // Maximum pool size | 最大协程数
	ScaleUpRate         float64       // Scale-up threshold | 扩容阈值
	ScaleDownRate       float64       // Scale-down threshold | 缩容阈值
	CheckInterval       time.Duration // Auto-scale check interval | 检查间隔
	Expiry              time.Duration // Idle worker expiry duration | 空闲协程过期时间
	PrintStatusInterval time.Duration // Interval for periodic status printing (0 = disabled) | 定时打印池状态的间隔（0表示关闭）
	PreAlloc            bool          // Whether to pre-allocate memory | 是否预分配内存
	NonBlocking         bool          // Whether to use non-blocking mode | 是否为非阻塞模式
}

// DefaultRenewPoolConfig returns default configuration | 返回默认配置
func DefaultRenewPoolConfig() *RenewPoolConfig {
	return &RenewPoolConfig{
		MinSize:       DefaultMinSize,
		MaxSize:       DefaultMaxSize,
		ScaleUpRate:   DefaultScaleUpRate,
		ScaleDownRate: DefaultScaleDownRate,
		CheckInterval: DefaultCheckInterval,
		Expiry:        DefaultExpiry,
		PreAlloc:      false,
		NonBlocking:   true,
	}
}

// RenewPoolManager manages a dynamic scaling goroutine pool for token renewal tasks | 续期任务协程池管理器
type RenewPoolManager struct {
	pool         *ants.Pool       // ants pool instance | ants 协程池实例
	config       *RenewPoolConfig // Configuration object | 池配置对象
	globalConfig *config.Config   // Global authentication configuration | 全局认证配置
	mu           sync.Mutex       // Synchronization lock | 互斥锁
	stopCh       chan struct{}    // Stop signal channel | 停止信号通道
	started      bool             // Indicates if pool manager is running | 是否已启动
	deps         *dep.Dep         // Dependencies manager | 依赖管理器
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

	// Start periodic pool status printer if interval is set | 若设置了打印间隔，则启动定时打印池状态的协程
	if cfg.PrintStatusInterval > 0 {
		go func() {
			ticker := time.NewTicker(cfg.PrintStatusInterval) // Create ticker for status printing | 创建定时器用于打印状态
			defer ticker.Stop()                               // Stop ticker on exit | 退出时停止定时器

			for {
				select {
				case <-ticker.C:
					mgr.PrintStatus() // Print current pool status | 打印当前协程池状态
				case <-mgr.stopCh:
					return // Exit when stop signal received | 收到停止信号后退出
				}
			}
		}()
	}

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
		return serror.ErrRenewPoolNotStarted
	}
	return m.pool.Submit(task)
}

// Stop stops the auto-scaling process | 停止自动扩缩容
func (m *RenewPoolManager) Stop() {
	if !m.started {
		return
	}
	close(m.stopCh)
	m.started = false

	if m.pool != nil && !m.pool.IsClosed() {
		_ = m.pool.ReleaseTimeout(5 * time.Second)
	}
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
			running := m.pool.Running()                   // Number of active goroutines | 当前正在执行的任务数
			capacity := m.pool.Cap()                      // Current pool capacity | 当前协程池容量
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

// Stats returns current pool statistics | 返回当前池状态
func (m *RenewPoolManager) Stats() (running, capacity int, usage float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	running = m.pool.Running()                   // Active tasks | 当前运行任务数
	capacity = m.pool.Cap()                      // Pool capacity | 当前池容量
	usage = float64(running) / float64(capacity) // Usage ratio | 当前使用率
	return
}

// PrintStatus prints current pool status | 打印池状态
func (m *RenewPoolManager) PrintStatus() {
	r, c, u := m.Stats()
	log.Infof("RenewPool Running: %d, Capacity: %d, Usage: %.1f%%", r, c, u*100)
}

// RenewPoolBuilder builder for RenewPoolManager | RenewPoolManager 构造器
type RenewPoolBuilder struct {
	cfg *RenewPoolConfig // Builder configuration | 构造器配置对象
}

// NewRenewPoolBuilder creates a new builder | 创建构造器
func NewRenewPoolBuilder() *RenewPoolBuilder {
	return &RenewPoolBuilder{cfg: DefaultRenewPoolConfig()}
}

// MinSize sets minimum pool size | 设置最小协程数
func (b *RenewPoolBuilder) MinSize(size int) *RenewPoolBuilder {
	b.cfg.MinSize = size
	return b
}

// MaxSize sets maximum pool size | 设置最大协程数
func (b *RenewPoolBuilder) MaxSize(size int) *RenewPoolBuilder {
	b.cfg.MaxSize = size
	return b
}

// ScaleUpRate sets the threshold for scaling up | 设置扩容阈值
func (b *RenewPoolBuilder) ScaleUpRate(up float64) *RenewPoolBuilder {
	b.cfg.ScaleUpRate = up
	return b
}

// ScaleDownRate sets the threshold for scaling down | 设置缩容阈值
func (b *RenewPoolBuilder) ScaleDownRate(down float64) *RenewPoolBuilder {
	b.cfg.ScaleDownRate = down
	return b
}

// CheckInterval sets auto-scaling check interval | 设置检查间隔
func (b *RenewPoolBuilder) CheckInterval(interval time.Duration) *RenewPoolBuilder {
	b.cfg.CheckInterval = interval
	return b
}

// Expiry sets worker expiry duration | 设置空闲协程过期时间
func (b *RenewPoolBuilder) Expiry(expiry time.Duration) *RenewPoolBuilder {
	b.cfg.Expiry = expiry
	return b
}

// PrintStatusInterval sets the interval for printing pool status | 设置打印状态的间隔
func (b *RenewPoolBuilder) PrintStatusInterval(interval time.Duration) *RenewPoolBuilder {
	b.cfg.PrintStatusInterval = interval
	return b
}

// PreAlloc sets pre-allocation flag | 设置是否预分配内存
func (b *RenewPoolBuilder) PreAlloc(prealloc bool) *RenewPoolBuilder {
	b.cfg.PreAlloc = prealloc
	return b
}

// NonBlocking sets non-blocking mode | 设置是否非阻塞模式
func (b *RenewPoolBuilder) NonBlocking(nonblocking bool) *RenewPoolBuilder {
	b.cfg.NonBlocking = nonblocking
	return b
}

// Config returns the current RenewPoolConfig | 返回当前的续期池配置
func (b *RenewPoolBuilder) Config() *RenewPoolConfig {
	return b.cfg
}

// Build constructs a RenewPoolManager instance | 构建 RenewPoolManager 实例
func (b *RenewPoolBuilder) Build() (*RenewPoolManager, error) {
	return NewRenewPoolManagerWithConfig(b.cfg)
}
