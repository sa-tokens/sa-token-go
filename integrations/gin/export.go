package gin

import (
	"github.com/click33/sa-token-go/core"
	"github.com/click33/sa-token-go/core/builder"
	"github.com/click33/sa-token-go/core/config"
	"github.com/click33/sa-token-go/core/manager"
	"github.com/click33/sa-token-go/log/slog"
	"github.com/click33/sa-token-go/pool/ants"
	"github.com/click33/sa-token-go/stputil"
)

var (
	ErrNotLogin           = core.ErrNotLogin              // token has been kicked out | Token 已被踢下线
	ErrTokenKickout       = core.ErrTokenKickout          // token has been kicked out | Token 已被踢下线
	ErrTokenReplaced      = core.ErrTokenReplaced         // token has been replaced | Token 已被顶下线
	ErrAccountDisabled    = core.ErrAccountDisabled       // account is disabled | 账号已被禁用
	ErrLoginLimitExceeded = manager.ErrLoginLimitExceeded // login count exceeds the maximum limit | 超出最大登录数量限制
)

func SetManager(mgr *manager.Manager) {
	stputil.SetManager(mgr)
}

func GetManager(autoType ...string) (*manager.Manager, error) {
	return stputil.GetManager(autoType...)
}

func DeleteManager(autoType ...string) error {
	return stputil.DeleteManager(autoType...)
}

func DeleteAllManager() {
	stputil.DeleteAllManager()
}

func NewDefaultBuild() *builder.Builder {
	return builder.NewBuilder()
}

func NewDefaultConfig() *config.Config {
	return config.DefaultConfig()
}

func DefaultLoggerConfig() *slog.LoggerConfig {
	return slog.DefaultLoggerConfig()
}

func DefaultRenewPoolConfig() *ants.RenewPoolConfig {
	return ants.DefaultRenewPoolConfig()
}
