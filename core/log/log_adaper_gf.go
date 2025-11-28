// @Author daixk 2025/11/27 22:58:00
package log

import (
	"context"
	"github.com/gogf/gf/v2/os/glog"
)

// GFLogger adapts GoFrame v2 glog.Logger to Sa-Token logger interface | GoFrame v2 glog 适配器
type GFLogger struct {
	l   *glog.Logger
	ctx context.Context
}

// NewGFLogger creates a logger based on GoFrame v2 glog | 创建基于 GoFrame v2 glog 的日志器
func NewGFLogger(l *glog.Logger) Adapter {
	if l == nil {
		l = glog.New()
	}
	return &GFLogger{
		l:   l,
		ctx: context.Background(),
	}
}

// SetContext sets logging context | 设置日志 Context
func (g *GFLogger) SetContext(ctx context.Context) {
	if ctx != nil {
		g.ctx = ctx
	}
}

// ---- Implement Adapter Interface | 实现 Adapter 接口 ----

func (g *GFLogger) Print(v ...any) {
	g.l.Print(g.ctx, v...)
}

func (g *GFLogger) Printf(format string, v ...any) {
	g.l.Printf(g.ctx, format, v...)
}

func (g *GFLogger) Debug(v ...any) {
	g.l.Debug(g.ctx, v...)
}

func (g *GFLogger) Debugf(format string, v ...any) {
	g.l.Debugf(g.ctx, format, v...)
}

func (g *GFLogger) Info(v ...any) {
	g.l.Info(g.ctx, v...)
}

func (g *GFLogger) Infof(format string, v ...any) {
	g.l.Infof(g.ctx, format, v...)
}

func (g *GFLogger) Warn(v ...any) {
	g.l.Warning(g.ctx, v...)
}

func (g *GFLogger) Warnf(format string, v ...any) {
	g.l.Warningf(g.ctx, format, v...)
}

func (g *GFLogger) Error(v ...any) {
	g.l.Error(g.ctx, v...)
}

func (g *GFLogger) Errorf(format string, v ...any) {
	g.l.Errorf(g.ctx, format, v...)
}
