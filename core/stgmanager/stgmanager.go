// @Author daixk 2025/12/7 12:58:00
package stgmanager

import (
	"errors"
	"github.com/click33/sa-token-go/core/manager"
	"sync"
)

// StgManager 管理多个 StgManager 实例 | Manages multiple StgManager instances
type StgManager struct {
	stpLogicMap sync.Map // 使用 sync.Map 替代 map 和 RWMutex | Replaces map and RWMutex with sync.Map
}

var (
	// defaultStgManager 是一个全局变量，表示默认的 StgManager 实例 | The default global StgManager instance
	defaultStgManager *StgManager
)

// NewStgManager 创建 StgManager 实例 | Creates an instance of StgManager
func NewStgManager() *StgManager {
	return &StgManager{}
}

// Init 初始化默认的 StgManager 实例 | Initializes the default StgManager instance
// 此方法将创建一个新的 StgManager 实例并将其赋值为默认实例 | This method creates a new StgManager instance and assigns it as the default instance
func (m *StgManager) init() {
	defaultStgManager = NewStgManager() // 创建一个新的 StgManager 实例 | Creates a new StgManager instance
}

// PutStgLogic 向 StgManager 中添加一个 StgManager 实例 | Adds a StgManager instance to the StgManager
func (m *StgManager) PutStgLogic(loginType string, logic *manager.Manager) {
	m.stpLogicMap.Store(loginType, logic) // 使用 Store 方法将数据存入 sync.Map | Use Store method to store data in sync.Map
}

// GetStgLogic 根据 loginType 获取对应的 StgManager 实例 | Retrieves the StgManager instance by loginType
func (m *StgManager) GetStgLogic(loginType string) (*manager.Manager, error) {
	value, exists := m.stpLogicMap.Load(loginType) // 使用 Load 方法从 sync.Map 中获取数据 | Use Load method to get data from sync.Map
	if !exists {
		return nil, errors.New("StgLogic not found for loginType: " + loginType)
	}
	logic, ok := value.(*manager.Manager) // 将获取的值断言为正确的类型 | Assert the retrieved value to the correct type
	if !ok {
		return nil, errors.New("Invalid StgLogic type")
	}
	return logic, nil
}

// InitDefaultStgManager 初始化并返回默认的 StgManager 实例 | Initializes and returns the default StgManager instance
// 如果默认实例尚未创建，则会初始化并返回 | If the default instance hasn't been created, it initializes and returns it
func InitDefaultStgManager() *StgManager {
	if defaultStgManager == nil {
		defaultStgManager = NewStgManager() // 初始化默认 StgManager 实例 | Initialize the default StgManager instance
	}
	return defaultStgManager
}
