package kratos

import (
	"context"
	"github.com/click33/sa-token-go/core"
	"net/http"

	"github.com/go-kratos/kratos/v2/errors"
)

// PluginOptions 认证引擎配置选项
type PluginOptions struct {
	// SkipOperations 跳过认证的operations（支持通配符）
	SkipOperations []string

	// DefaultRequireLogin 默认是否需要登录（如果没有匹配的规则，使用此默认值）
	DefaultRequireLogin bool

	// ErrorHandler 自定义错误处理器
	ErrorHandler func(ctx context.Context, err error) error
}

// defaultPluginOptions 返回默认配置
func defaultPluginOptions() *PluginOptions {
	return &PluginOptions{
		SkipOperations:      []string{},
		DefaultRequireLogin: false,
		ErrorHandler:        defaultErrorHandler,
	}
}

// defaultErrorHandler 默认错误处理器
func defaultErrorHandler(ctx context.Context, err error) error {
	var saErr *core.SaTokenError
	var code int
	var message string
	var httpStatus int
	var reason string
	// Check if it's a SaTokenError | 检查是否为SaTokenError
	if errors.As(err, &saErr) {
		code = saErr.Code
		message = saErr.Message
		httpStatus = getHTTPStatusFromCode(code)
		reason = getReasonFromCode(code)
	} else {
		// Handle standard errors | 处理标准错误
		code = core.CodeServerError
		message = err.Error()
		httpStatus = http.StatusInternalServerError
		reason = getReasonFromCode(code)
	}

	return errors.Errorf(httpStatus, reason, message)
}

// ========== Option模式 ==========

// Option 配置函数
type Option func(*PluginOptions)

// WithSkipOperations 设置跳过的operations
func WithSkipOperations(operations ...string) Option {
	return func(o *PluginOptions) {
		o.SkipOperations = append(o.SkipOperations, operations...)
	}
}

// WithDefaultRequireLogin 设置默认是否需要登录
func WithDefaultRequireLogin(require bool) Option {
	return func(o *PluginOptions) {
		o.DefaultRequireLogin = require
	}
}

// WithErrorHandler 设置自定义错误处理器
func WithErrorHandler(handler func(ctx context.Context, err error) error) Option {
	return func(o *PluginOptions) {
		o.ErrorHandler = handler
	}
}

// getHTTPStatusFromCode converts Sa-Token error code to HTTP status | 将Sa-Token错误码转换为HTTP状态码
func getHTTPStatusFromCode(code int) int {
	switch code {
	case core.CodeNotLogin:
		return http.StatusUnauthorized
	case core.CodePermissionDenied:
		return http.StatusForbidden
	case core.CodeBadRequest:
		return http.StatusBadRequest
	case core.CodeNotFound:
		return http.StatusNotFound
	case core.CodeServerError:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

func getReasonFromCode(code int) string {
	switch code {
	case core.CodeNotLogin:
		return "UNAUTHORIZED"
	case core.CodePermissionDenied:
		return "FORBIDDEN"
	case core.CodeBadRequest:
		return "BAD_REQUEST"
	case core.CodeNotFound:
		return "NOT_FOUND"
	case core.CodeServerError:
		return "INTERNAL_SERVER_ERROR"
	default:
		return "INTERNAL_SERVER_ERROR"
	}
}
