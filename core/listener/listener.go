package listener

import (
	"fmt"
	"github.com/click33/sa-token-go/core/adapter"
	"github.com/click33/sa-token-go/log/nop"
	"sync"
	"time"
)

// EventData contains information about a triggered event | 事件数据，包含触发事件的相关信息
type EventData struct {
	Event     Event          // Event type | 事件类型
	AuthType  string         // Authentication system type | 认证体系类型
	LoginID   string         // User login ID | 用户登录ID
	Device    string         // Device identifier | 设备标识
	Token     string         // Authentication token | 认证Token
	Extra     map[string]any // Additional custom data | 额外的自定义数据
	Timestamp int64          // Unix timestamp when event was triggered | 事件触发的Unix时间戳
}

// String returns a string representation of the event data | 返回事件数据的字符串表示
func (e *EventData) String() string {
	return fmt.Sprintf("Event{type=%s,AuthType=%s, loginID=%s, device=%s, timestamp=%d}",
		e.Event, e.AuthType, e.LoginID, e.Device, e.Timestamp)
}

// Listener is the interface for event listeners | 事件监听器接口
type Listener interface {
	// OnEvent is called when an event is triggered | 当事件触发时调用
	// The listener should not panic; any panic will be recovered by the event manager-example | 监听器不应该panic，任何panic都会被事件管理器恢复
	OnEvent(data *EventData)
}

// ListenerFunc is a function adapter that implements the Listener interface | 函数适配器，实现Listener接口
type ListenerFunc func(data *EventData)

// OnEvent implements the Listener interface | 实现Listener接口
func (f ListenerFunc) OnEvent(data *EventData) {
	f(data)
}

// ListenerConfig holds configuration for a registered listener | 监听器配置
type ListenerConfig struct {
	Async    bool   // If true, listener runs asynchronously | 如果为true，监听器异步运行
	Priority int    // Higher priority listeners are called first (log: 0) | 优先级越高越先执行（默认：0）
	ID       string // Unique identifier for this listener (for unregistering) | 监听器唯一标识（用于注销）
}

type listenerEntry struct {
	listener Listener
	config   ListenerConfig
}

// EventFilter is a function that decides whether an event should be processed | 事件过滤器，决定事件是否应该被处理
type EventFilter func(data *EventData) bool

// EventStats contains statistics about event processing | 事件统计信息
type EventStats struct {
	TotalTriggered int64               // Total number of events triggered | 触发的事件总数
	EventCounts    map[Event]int64     // Count per event type | 各类型事件的计数
	LastTriggered  map[Event]time.Time // Last trigger time per event | 各类型事件的最后触发时间
}

// Manager manages event listeners and dispatches events | 事件管理器，管理监听器并分发事件
type Manager struct {
	mu              sync.RWMutex
	listeners       map[Event][]listenerEntry
	panicHandler    func(event Event, data *EventData, recovered any)
	listenerCounter int
	enabledEvents   map[Event]bool // If nil, all events are enabled | 如果为nil，所有事件都启用
	asyncWaitGroup  sync.WaitGroup // For waiting on async listeners during shutdown | 用于等待异步监听器完成
	filters         []EventFilter  // Global event filters | 全局事件过滤器
	stats           *EventStats    // Event statistics | 事件统计
	enableStats     bool           // Whether to collect statistics | 是否收集统计信息
	logger          adapter.Log    // Log adapter for logging operations | 日志适配器
}

// NewManager creates a new event manager-example | 创建新的事件管理器
func NewManager(loggers ...adapter.Log) *Manager {
	var logger adapter.Log

	if len(loggers) > 0 && loggers[0] != nil {
		logger = loggers[0]
	} else {
		logger = nop.NewNopLogger()
	}

	m := &Manager{
		listeners:     make(map[Event][]listenerEntry),
		enabledEvents: nil, // All events enabled by log | 默认启用所有事件
		filters:       make([]EventFilter, 0),
		stats: &EventStats{
			EventCounts:   make(map[Event]int64),
			LastTriggered: make(map[Event]time.Time),
		},
		enableStats: false, // Stats disabled by log | 默认不启用统计
		logger:      logger,
	}

	// panicHandler 绑定“已经确定好的 logger”
	m.panicHandler = func(event Event, data *EventData, recovered any) {
		logger.Errorf(
			"Listener listener panic recovered: event=%s, panic=%v",
			event, recovered,
		)
	}

	return m
}

// SetPanicHandler sets a custom panic handler for listener errors | 设置自定义的panic处理器
func (m *Manager) SetPanicHandler(handler func(event Event, data *EventData, recovered any)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.panicHandler = handler
}

// AddFilter adds a global event filter | 添加全局事件过滤器
func (m *Manager) AddFilter(filter EventFilter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.filters = append(m.filters, filter)
}

// ClearFilters removes all event filters | 清除所有事件过滤器
func (m *Manager) ClearFilters() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.filters = make([]EventFilter, 0)
}

// EnableStats enables event statistics collection | 启用事件统计
func (m *Manager) EnableStats(enable bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enableStats = enable
}

// GetStats returns a copy of event statistics | 获取事件统计信息副本
func (m *Manager) GetStats() EventStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := EventStats{
		TotalTriggered: m.stats.TotalTriggered,
		EventCounts:    make(map[Event]int64),
		LastTriggered:  make(map[Event]time.Time),
	}

	for event, count := range m.stats.EventCounts {
		stats.EventCounts[event] = count
	}
	for event, t := range m.stats.LastTriggered {
		stats.LastTriggered[event] = t
	}

	return stats
}

// ResetStats resets event statistics | 重置事件统计
func (m *Manager) ResetStats() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats = &EventStats{
		EventCounts:   make(map[Event]int64),
		LastTriggered: make(map[Event]time.Time),
	}
}

// EnableEvent enables specific events (disables all others) | 启用特定事件（禁用其他所有事件）
// Call with no arguments to enable all events | 不传参数时启用所有事件
func (m *Manager) EnableEvent(events ...Event) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(events) == 0 {
		m.enabledEvents = nil // Enable all | 启用所有
		return
	}

	m.enabledEvents = make(map[Event]bool)
	for _, event := range events {
		m.enabledEvents[event] = true
	}
}

// DisableEvent disables specific events | 禁用特定事件
func (m *Manager) DisableEvent(events ...Event) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.enabledEvents == nil {
		m.enabledEvents = make(map[Event]bool)
		// Add all existing events
		for event := range m.listeners {
			m.enabledEvents[event] = true
		}
	}

	for _, event := range events {
		delete(m.enabledEvents, event)
	}
}

// IsEventEnabled checks if an event is enabled
func (m *Manager) IsEventEnabled(event Event) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.enabledEvents == nil {
		return true // All events enabled
	}

	return m.enabledEvents[event] || m.enabledEvents[EventAll]
}

// Register registers a listener for an event with log configuration
func (m *Manager) Register(event Event, listener Listener) string {
	return m.RegisterWithConfig(event, listener, ListenerConfig{
		Async:    true,
		Priority: 0,
	})
}

// RegisterWithConfig registers a listener with custom configuration
func (m *Manager) RegisterWithConfig(event Event, listener Listener, config ListenerConfig) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Generate unique ID if not provided
	if config.ID == "" {
		m.listenerCounter++
		config.ID = fmt.Sprintf("listener_%d", m.listenerCounter)
	}

	if m.listeners[event] == nil {
		m.listeners[event] = make([]listenerEntry, 0)
	}

	entry := listenerEntry{
		listener: listener,
		config:   config,
	}

	m.listeners[event] = append(m.listeners[event], entry)

	// Sort by priority (higher first)
	m.sortListeners(event)

	return config.ID
}

// RegisterFunc registers a function listener with log configuration
func (m *Manager) RegisterFunc(event Event, handler func(data *EventData)) string {
	return m.Register(event, ListenerFunc(handler))
}

// RegisterFuncWithConfig registers a function listener with custom configuration
func (m *Manager) RegisterFuncWithConfig(event Event, handler func(data *EventData), config ListenerConfig) string {
	return m.RegisterWithConfig(event, ListenerFunc(handler), config)
}

// Unregister removes a listener by its ID
func (m *Manager) Unregister(listenerID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	for event, entries := range m.listeners {
		for i, entry := range entries {
			if entry.config.ID == listenerID {
				// Remove this entry
				m.listeners[event] = append(entries[:i], entries[i+1:]...)
				return true
			}
		}
	}

	return false
}

// sortListeners sorts listeners by priority (descending)
func (m *Manager) sortListeners(event Event) {
	entries := m.listeners[event]
	// Use insertion sort (efficient for small lists and maintains stability)
	for i := 1; i < len(entries); i++ {
		key := entries[i]
		j := i - 1
		for j >= 0 && entries[j].config.Priority < key.config.Priority {
			entries[j+1] = entries[j]
			j--
		}
		entries[j+1] = key
	}
}

// Trigger dispatches an event to all registered listeners
func (m *Manager) Trigger(data *EventData) {
	m.mu.RLock()

	// Check if event is enabled
	if !m.IsEventEnabled(data.Event) {
		m.mu.RUnlock()
		return
	}

	// Set timestamp if not already set
	if data.Timestamp == 0 {
		data.Timestamp = time.Now().Unix()
	}

	// Apply filters
	for _, filter := range m.filters {
		if !filter(data) {
			m.mu.RUnlock()
			return // Event filtered out
		}
	}

	// Update statistics
	if m.enableStats {
		m.stats.TotalTriggered++
		m.stats.EventCounts[data.Event]++
		m.stats.LastTriggered[data.Event] = time.Now()
	}

	// Collect listeners to call
	var listenersToCall []listenerEntry

	// Event-specific listeners
	if listeners, ok := m.listeners[data.Event]; ok {
		listenersToCall = append(listenersToCall, listeners...)
	}

	// Wildcard listeners
	if listeners, ok := m.listeners[EventAll]; ok {
		listenersToCall = append(listenersToCall, listeners...)
	}

	m.mu.RUnlock()

	// 日志
	m.logger.Infof(
		"Listener auth event triggered: event=%s, authType=%s, loginID=%s, device=%s, listeners=%d",
		data.Event,
		data.AuthType,
		data.LoginID,
		data.Device,
		len(listenersToCall),
	)

	// Execute listeners
	for _, entry := range listenersToCall {
		if entry.config.Async {
			m.asyncWaitGroup.Add(1)
			go m.safeCall(entry.listener, data, &m.asyncWaitGroup)
		} else {
			m.safeCall(entry.listener, data, nil)
		}
	}
}

// TriggerAsync triggers an event asynchronously and returns immediately | 异步触发事件并立即返回
func (m *Manager) TriggerAsync(data *EventData) {
	go m.Trigger(data)
}

// TriggerSync triggers an event synchronously and waits for all listeners | 同步触发事件并等待所有监听器完成
func (m *Manager) TriggerSync(data *EventData) {
	m.Trigger(data)
	m.Wait()
}

// safeCall executes a listener with panic recovery
func (m *Manager) safeCall(listener Listener, data *EventData, wg *sync.WaitGroup) {
	if wg != nil {
		defer wg.Done()
	}

	defer func() {
		if r := recover(); r != nil {
			m.mu.RLock()
			handler := m.panicHandler
			m.mu.RUnlock()

			if handler != nil {
				handler(data.Event, data, r)
			}
		}
	}()

	listener.OnEvent(data)
}

// Wait waits for all async listeners to complete (useful for testing/shutdown)
func (m *Manager) Wait() {
	m.asyncWaitGroup.Wait()
}

// Clear removes all listeners
func (m *Manager) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listeners = make(map[Event][]listenerEntry)
}

// ClearEvent removes all listeners for a specific event
func (m *Manager) ClearEvent(event Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.listeners, event)
}

// Count returns the total number of registered listeners
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for _, entries := range m.listeners {
		count += len(entries)
	}
	return count
}

// CountForEvent returns the number of listeners for a specific event
func (m *Manager) CountForEvent(event Event) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.listeners[event])
}

// GetListenerIDs returns all listener IDs for a specific event | 获取指定事件的所有监听器ID
func (m *Manager) GetListenerIDs(event Event) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entries := m.listeners[event]
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		ids = append(ids, entry.config.ID)
	}
	return ids
}

// GetAllEvents returns all events that have registered listeners | 获取所有已注册监听器的事件
func (m *Manager) GetAllEvents() []Event {
	m.mu.RLock()
	defer m.mu.RUnlock()

	events := make([]Event, 0, len(m.listeners))
	for event := range m.listeners {
		events = append(events, event)
	}
	return events
}

// HasListeners checks if there are any listeners for a specific event | 检查指定事件是否有监听器
func (m *Manager) HasListeners(event Event) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.listeners[event]) > 0
}
