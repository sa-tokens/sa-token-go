package kratos

import (
	"context"
	"sort"
	"strings"

	"github.com/click33/sa-token-go/core"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
)

// Plugin 认证引擎
type Plugin struct {
	manager *core.Manager
	rules   []Rule
	options *PluginOptions
}

// Rule 认证规则
type Rule struct {
	// Matcher operation匹配器
	Matcher OperationMatcher
	// Checkers 检查器链
	Checkers []Checker
	// Priority 规则优先级（数字越大优先级越高，默认0）
	Priority int
}

// NewPlugin 创建认证插件
func NewPlugin(manager *core.Manager, opts ...*PluginOptions) *Plugin {
	plugin := &Plugin{
		manager: manager,
		rules:   make([]Rule, 0),
	}

	if len(opts) > 0 && opts[0] != nil {
		plugin.options = opts[0]
	} else {
		plugin.options = defaultPluginOptions()
	}

	return plugin
}

// Server 返回Kratos中间件
func (e *Plugin) Server() middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (reply interface{}, err error) {
			info, ok := transport.FromServerContext(ctx)
			if !ok {
				// 无法获取传输层信息，直接放行
				return handler(ctx, req)
			}

			kratosContext := NewKratosContext(ctx)
			saCtx := core.NewContext(kratosContext, e.manager)
			operation := info.Operation()

			if e.shouldSkip(operation) {
				return handler(ctx, req)
			}

			rule, found := e.findRule(operation)

			if !found {
				if e.options.DefaultRequireLogin {
					if !saCtx.IsLogin() {
						return nil, e.options.ErrorHandler(ctx, core.ErrNotLogin)
					}
				}
				ctx = context.WithValue(ctx, "satoken", saCtx)
				return handler(ctx, req)
			}

			loginID, err := saCtx.GetLoginID()
			if err != nil {
				return nil, e.options.ErrorHandler(ctx, core.ErrNotLogin)
			}

			for _, checker := range rule.Checkers {
				if err := checker.Check(ctx, e.manager, loginID); err != nil {
					return nil, e.options.ErrorHandler(ctx, err)
				}
			}

			ctx = context.WithValue(ctx, "satoken", saCtx)
			return handler(ctx, req)
		}
	}
}

// ========== 规则构建器 ==========

// RuleBuilder 规则构建器（链式API）
type RuleBuilder struct {
	plugin   *Plugin
	matcher  OperationMatcher
	checkers []Checker
	priority int
}

// AutoMatcher 匹配指定operation（自动选择matcher类型）
func (e *Plugin) AutoMatcher(pattern string) *RuleBuilder {
	return &RuleBuilder{
		plugin:   e,
		matcher:  newPatternMatcher(pattern),
		checkers: make([]Checker, 0),
		priority: 0,
	}
}

// ExactMatcher 精确匹配
func (e *Plugin) ExactMatcher(operation string) *RuleBuilder {
	return &RuleBuilder{
		plugin:   e,
		matcher:  &ExactMatcher{operation: operation},
		checkers: make([]Checker, 0),
	}
}

// PrefixMatcher 前缀匹配
func (e *Plugin) PrefixMatcher(prefix string) *RuleBuilder {
	return &RuleBuilder{
		plugin:   e,
		matcher:  &PrefixMatcher{prefix: prefix},
		checkers: make([]Checker, 0),
	}
}

// SuffixMatcher 后缀匹配
func (e *Plugin) SuffixMatcher(suffix string) *RuleBuilder {
	return &RuleBuilder{
		plugin:   e,
		matcher:  &SuffixMatcher{suffix: suffix},
		checkers: make([]Checker, 0),
	}
}

// PatternMatcher 通配符匹配
func (e *Plugin) PatternMatcher(pattern string) *RuleBuilder {
	return &RuleBuilder{
		plugin:   e,
		matcher:  &WildcardMatcher{pattern: pattern},
		checkers: make([]Checker, 0),
	}
}

// RegexMatcher 正则匹配
func (e *Plugin) RegexMatcher(regex string) *RuleBuilder {
	return &RuleBuilder{
		plugin:   e,
		matcher:  newRegexMatcher(regex),
		checkers: make([]Checker, 0),
	}
}

// ContainsMatcher 包含匹配
func (e *Plugin) ContainsMatcher(substring string) *RuleBuilder {
	return &RuleBuilder{
		plugin:   e,
		matcher:  &ContainsMatcher{substring: substring},
		checkers: make([]Checker, 0),
	}
}

// FuncMatcher 自定义匹配函数
func (e *Plugin) FuncMatcher(fn func(operation string) bool, name ...string) *RuleBuilder {
	return &RuleBuilder{
		plugin:   e,
		matcher:  &FuncMatcher{fn: fn},
		checkers: make([]Checker, 0),
	}
}

// CustomMatcher 使用自定义matcher
func (e *Plugin) CustomMatcher(matcher OperationMatcher) *RuleBuilder {
	return &RuleBuilder{
		plugin:   e,
		matcher:  matcher,
		checkers: make([]Checker, 0),
	}
}

// ========== RuleBuilder 方法 ==========

// RequireLogin 需要登录
func (rb *RuleBuilder) RequireLogin() *RuleBuilder {
	rb.checkers = append(rb.checkers, &LoginChecker{})
	return rb
}

// RequirePermission 需要指定权限
func (rb *RuleBuilder) RequirePermission(permission string) *RuleBuilder {
	rb.checkers = append(rb.checkers, &PermissionChecker{permission: permission})
	return rb
}

// RequirePermissions 需要多个权限（AND逻辑）
func (rb *RuleBuilder) RequirePermissions(permissions ...string) *RuleBuilder {
	rb.checkers = append(rb.checkers, &PermissionsAndChecker{permissions: permissions})
	return rb
}

// RequireAnyPermission 需要任一权限（OR逻辑）
func (rb *RuleBuilder) RequireAnyPermission(permissions ...string) *RuleBuilder {
	rb.checkers = append(rb.checkers, &PermissionsOrChecker{permissions: permissions})
	return rb
}

// RequireRole 需要指定角色
func (rb *RuleBuilder) RequireRole(role string) *RuleBuilder {
	rb.checkers = append(rb.checkers, &RoleChecker{role: role})
	return rb
}

// RequireRoles 需要多个角色（AND逻辑）
func (rb *RuleBuilder) RequireRoles(roles ...string) *RuleBuilder {
	rb.checkers = append(rb.checkers, &RolesAndChecker{roles: roles})
	return rb
}

// RequireAnyRole 需要任一角色（OR逻辑）
func (rb *RuleBuilder) RequireAnyRole(roles ...string) *RuleBuilder {
	rb.checkers = append(rb.checkers, &RolesOrChecker{roles: roles})
	return rb
}

// CheckNotDisabled 检查账号未被封禁
func (rb *RuleBuilder) CheckNotDisabled() *RuleBuilder {
	rb.checkers = append(rb.checkers, &DisableChecker{})
	return rb
}

// CustomCheck 自定义检查
func (rb *RuleBuilder) CustomCheck(name string, fn func(ctx context.Context, manager *core.Manager, loginID string) error) *RuleBuilder {
	rb.checkers = append(rb.checkers, &CustomChecker{name: name, fn: fn})
	return rb
}

// AddChecker 添加自定义checker
func (rb *RuleBuilder) AddChecker(checker Checker) *RuleBuilder {
	rb.checkers = append(rb.checkers, checker)
	return rb
}

// WithPriority 设置优先级
func (rb *RuleBuilder) WithPriority(priority int) *RuleBuilder {
	rb.priority = priority
	return rb
}

// Build 构建规则并添加到引擎
func (rb *RuleBuilder) Build() *Plugin {
	rule := Rule{
		Matcher:  rb.matcher,
		Checkers: rb.checkers,
		Priority: rb.priority,
	}
	rb.plugin.addRule(rule)
	return rb.plugin
}

// ========== Plugin便捷方法 ==========

// Skip 跳过指定operations
func (e *Plugin) Skip(operations ...string) *Plugin {
	e.options.SkipOperations = append(e.options.SkipOperations, operations...)
	return e
}

// DefaultRequireLogin 设置默认需要登录
func (e *Plugin) DefaultRequireLogin(require bool) *Plugin {
	e.options.DefaultRequireLogin = require
	return e
}

// SetErrorHandler 设置错误处理器
func (e *Plugin) SetErrorHandler(handler func(ctx context.Context, err error) error) *Plugin {
	e.options.ErrorHandler = handler
	return e
}

// AddRule 直接添加规则
func (e *Plugin) AddRule(rule Rule) *Plugin {
	e.addRule(rule)
	return e
}

// AddRules 批量添加规则
func (e *Plugin) AddRules(rules ...Rule) *Plugin {
	for _, rule := range rules {
		e.addRule(rule)
	}
	return e
}

// ========== 内部方法 ==========

func (e *Plugin) shouldSkip(operation string) bool {
	for _, pattern := range e.options.SkipOperations {
		if matchPattern(pattern, operation) {
			return true
		}
	}
	return false
}

func (e *Plugin) findRule(operation string) (Rule, bool) {
	var matchedRules []Rule

	// 找出所有匹配的规则
	for _, rule := range e.rules {
		if rule.Matcher.Match(operation) {
			matchedRules = append(matchedRules, rule)
		}
	}

	if len(matchedRules) == 0 {
		return Rule{}, false
	}

	// 按优先级排序（降序）
	sort.Slice(matchedRules, func(i, j int) bool {
		return matchedRules[i].Priority > matchedRules[j].Priority
	})

	// 返回优先级最高的规则
	return matchedRules[0], true
}

func (e *Plugin) addRule(rule Rule) {
	e.rules = append(e.rules, rule)
}

func matchPattern(pattern, str string) bool {
	// 完全匹配
	if pattern == str {
		return true
	}

	// 通配符 *
	if pattern == "*" {
		return true
	}

	// 前缀匹配 prefix*
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(str, prefix)
	}

	// 后缀匹配 *suffix
	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(str, suffix)
	}

	// 通配符匹配
	if strings.Contains(pattern, "*") || strings.Contains(pattern, "?") {
		return wildcardMatch(pattern, str)
	}

	return false
}
