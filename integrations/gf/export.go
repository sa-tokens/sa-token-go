package gf

import (
	"github.com/click33/sa-token-go/core/builder"
	"github.com/click33/sa-token-go/core/config"
	"github.com/click33/sa-token-go/core/manager"
	"github.com/click33/sa-token-go/stputil"
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

func DefaultLoggerConfig() *config.LoggerConfig {
	return config.DefaultLoggerConfig()
}

func DefaultDefaultRenewPoolConfig() *config.RenewPoolConfig {
	return config.DefaultRenewPoolConfig()
}
