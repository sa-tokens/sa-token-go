// @Author daixk 2025/11/17 9:35:00
package adapter

import (
	"context"
	"github.com/gogf/gf/v2/os/glog"
)

// LogAdapterGf implements log.ILogger using GoFrame glog | 使用 GoFrame glog 实现 ILogger 接口
type LogAdapterGf struct {
	logger *glog.Logger    // Internal glog instance | 内部 glog 实例
	ctx    context.Context // Context for glog | 日志上下文
}

// NewLogAdapterGf creates a new Gf logger adapter | 创建新的 glog 日志适配器
func NewLogAdapterGf() *LogAdapterGf {
	return &LogAdapterGf{
		logger: glog.New(),
		ctx:    context.Background(),
	}
}
