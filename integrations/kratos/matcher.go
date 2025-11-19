package kratos

import (
	"regexp"
	"strings"
)

// OperationMatcher operation匹配器接口
type OperationMatcher interface {
	Match(operation string) bool
}

// ========== 精确匹配 ==========

// ExactMatcher 精确匹配
type ExactMatcher struct {
	operation string
}

func (m *ExactMatcher) Match(operation string) bool {
	return m.operation == operation
}

// ========== 前缀匹配 ==========

// PrefixMatcher 前缀匹配
type PrefixMatcher struct {
	prefix string
}

func (m *PrefixMatcher) Match(operation string) bool {
	return strings.HasPrefix(operation, m.prefix)
}

// ========== 后缀匹配 ==========

// SuffixMatcher 后缀匹配
type SuffixMatcher struct {
	suffix string
}

func (m *SuffixMatcher) Match(operation string) bool {
	return strings.HasSuffix(operation, m.suffix)
}

// ========== 通配符匹配 ==========

// WildcardMatcher 通配符匹配（支持 * 和 ?）
// * 匹配任意字符（包括空字符串）
// ? 匹配单个字符
type WildcardMatcher struct {
	pattern string
}

func (m *WildcardMatcher) Match(operation string) bool {
	return wildcardMatch(m.pattern, operation)
}

// wildcardMatch 实现通配符匹配算法
func wildcardMatch(pattern, str string) bool {
	pLen := len(pattern)
	sLen := len(str)
	pIdx := 0
	sIdx := 0
	starIdx := -1
	matchIdx := 0

	for sIdx < sLen {
		if pIdx < pLen && (pattern[pIdx] == str[sIdx] || pattern[pIdx] == '?') {
			pIdx++
			sIdx++
		} else if pIdx < pLen && pattern[pIdx] == '*' {
			starIdx = pIdx
			matchIdx = sIdx
			pIdx++
		} else if starIdx != -1 {
			pIdx = starIdx + 1
			matchIdx++
			sIdx = matchIdx
		} else {
			return false
		}
	}

	for pIdx < pLen && pattern[pIdx] == '*' {
		pIdx++
	}

	return pIdx == pLen
}

// ========== 正则匹配 ==========

// RegexMatcher 正则表达式匹配
type RegexMatcher struct {
	regex *regexp.Regexp
}

func newRegexMatcher(pattern string) *RegexMatcher {
	re, err := regexp.Compile(pattern)
	if err != nil {
		// 如果编译失败，返回永不匹配的matcher
		return &RegexMatcher{regex: regexp.MustCompile("^$")}
	}
	return &RegexMatcher{regex: re}
}

func (m *RegexMatcher) Match(operation string) bool {
	return m.regex.MatchString(operation)
}

// ========== 包含匹配 ==========

// ContainsMatcher 包含匹配
type ContainsMatcher struct {
	substring string
}

func (m *ContainsMatcher) Match(operation string) bool {
	return strings.Contains(operation, m.substring)
}

// ========== 函数匹配 ==========

// FuncMatcher 自定义函数匹配
type FuncMatcher struct {
	fn func(operation string) bool
}

func (m *FuncMatcher) Match(operation string) bool {
	return m.fn(operation)
}

// ========== 组合匹配 ==========

// AndMatcher AND组合匹配（所有matcher都匹配才返回true）
type AndMatcher struct {
	matchers []OperationMatcher
}

func (m *AndMatcher) Match(operation string) bool {
	for _, matcher := range m.matchers {
		if !matcher.Match(operation) {
			return false
		}
	}
	return true
}

// OrMatcher OR组合匹配（任一matcher匹配就返回true）
type OrMatcher struct {
	matchers []OperationMatcher
}

func (m *OrMatcher) Match(operation string) bool {
	for _, matcher := range m.matchers {
		if matcher.Match(operation) {
			return true
		}
	}
	return false
}

// NotMatcher NOT匹配（反转匹配结果）
type NotMatcher struct {
	matcher OperationMatcher
}

func (m *NotMatcher) Match(operation string) bool {
	return !m.matcher.Match(operation)
}

// ========== 便捷构造函数 ==========

// newPatternMatcher 根据pattern自动选择合适的matcher
func newPatternMatcher(pattern string) OperationMatcher {
	// 包含通配符，使用WildcardMatcher
	if strings.Contains(pattern, "*") || strings.Contains(pattern, "?") {
		return &WildcardMatcher{pattern: pattern}
	}
	// 精确匹配
	return &ExactMatcher{operation: pattern}
}

// And 创建AND组合匹配器
func And(matchers ...OperationMatcher) OperationMatcher {
	return &AndMatcher{matchers: matchers}
}

// Or 创建OR组合匹配器
func Or(matchers ...OperationMatcher) OperationMatcher {
	return &OrMatcher{matchers: matchers}
}

// Not 创建NOT匹配器
func Not(matcher OperationMatcher) OperationMatcher {
	return &NotMatcher{matcher: matcher}
}
