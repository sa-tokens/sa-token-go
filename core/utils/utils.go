package utils

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// Constants for time durations | 时间常量
const (
	Second = 1
	Minute = 60 * Second
	Hour   = 60 * Minute
	Day    = 24 * Hour
	Week   = 7 * Day
)

// Constants for string operations | 字符串操作常量
const (
	DefaultSeparator = ","
	WildcardChar     = "*"
)

// ============ Random Generation | 随机生成 ============

// RandomString generates random string of specified length | 生成指定长度的随机字符串
func RandomString(length int) string {
	if length <= 0 {
		return ""
	}

	// Calculate required byte length (base64 expands by ~33%)
	byteLen := (length * 3) / 4
	if byteLen < length {
		byteLen = length
	}

	bytes := make([]byte, byteLen)
	if _, err := rand.Read(bytes); err != nil {
		return ""
	}

	encoded := base64.URLEncoding.EncodeToString(bytes)
	// Remove padding and trim to exact length
	encoded = strings.TrimRight(encoded, "=")
	if len(encoded) > length {
		return encoded[:length]
	}
	return encoded
}

// RandomNumericString generates random numeric string | 生成随机数字字符串
func RandomNumericString(length int) string {
	if length <= 0 {
		return ""
	}

	const digits = "0123456789"
	result := make([]byte, length)
	max := big.NewInt(int64(len(digits)))

	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return ""
		}
		result[i] = digits[n.Int64()]
	}

	return string(result)
}

// RandomAlphanumeric generates random alphanumeric string | 生成随机字母数字字符串
func RandomAlphanumeric(length int) string {
	if length <= 0 {
		return ""
	}

	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	max := big.NewInt(int64(len(chars)))

	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return ""
		}
		result[i] = chars[n.Int64()]
	}

	return string(result)
}

// IsEmpty checks if string is empty | 检查字符串是否为空
func IsEmpty(s string) bool {
	return strings.TrimSpace(s) == ""
}

// IsNotEmpty checks if string is not empty | 检查字符串是否不为空
func IsNotEmpty(s string) bool {
	return !IsEmpty(s)
}

// DefaultString returns default value if string is empty | 如果字符串为空则返回默认值
func DefaultString(s, defaultValue string) string {
	if IsEmpty(s) {
		return defaultValue
	}
	return s
}

// ContainsString checks if string slice contains item | 检查字符串数组是否包含指定字符串
func ContainsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// RemoveString removes item from string slice | 从字符串数组中移除指定字符串
func RemoveString(slice []string, item string) []string {
	result := make([]string, 0, len(slice))
	for _, s := range slice {
		if s != item {
			result = append(result, s)
		}
	}
	return result
}

// UniqueStrings removes duplicates from string slice | 字符串数组去重
func UniqueStrings(slice []string) []string {
	if len(slice) == 0 {
		return []string{}
	}

	seen := make(map[string]bool, len(slice))
	result := make([]string, 0, len(slice))
	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// FilterStrings filters string slice by predicate | 根据条件过滤字符串数组
func FilterStrings(slice []string, predicate func(string) bool) []string {
	result := make([]string, 0, len(slice))
	for _, s := range slice {
		if predicate(s) {
			result = append(result, s)
		}
	}
	return result
}

// MapStrings applies function to each string in slice | 对数组中每个字符串应用函数
func MapStrings(slice []string, mapper func(string) string) []string {
	result := make([]string, len(slice))
	for i, s := range slice {
		result[i] = mapper(s)
	}
	return result
}

// MergeStrings Merges multiple string slices and removes duplicates | 合并多个字符串数组并去重
func MergeStrings(slices ...[]string) []string {
	if len(slices) == 0 {
		return []string{}
	}

	// Pre-calculate total capacity
	totalLen := 0
	for _, slice := range slices {
		totalLen += len(slice)
	}

	result := make([]string, 0, totalLen)
	for _, slice := range slices {
		result = append(result, slice...)
	}
	return UniqueStrings(result)
}

// SplitAndTrim Splits string and trims whitespace | 分割字符串并去除空格
func SplitAndTrim(s, sep string) []string {
	if s == "" {
		return []string{}
	}

	parts := strings.Split(s, sep)
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// JoinNonEmpty Joins non-empty strings | 连接非空字符串
func JoinNonEmpty(sep string, strs ...string) string {
	nonEmpty := make([]string, 0, len(strs))
	for _, s := range strs {
		if IsNotEmpty(s) {
			nonEmpty = append(nonEmpty, s)
		}
	}
	return strings.Join(nonEmpty, sep)
}

// GetStructTag 获取结构体字段的标签值
func GetStructTag(field reflect.StructField, tag string) string {
	return field.Tag.Get(tag)
}

// ParsePermissionTag 解析权限标签
// 格式: "perm:user:read,user:write"
func ParsePermissionTag(tag string) []string {
	if tag == "" {
		return []string{}
	}

	// 移除 "perm:" 前缀
	tag = strings.TrimPrefix(tag, "perm:")
	return SplitAndTrim(tag, ",")
}

// ParseRoleTag 解析角色标签
// 格式: "role:admin,manager"
func ParseRoleTag(tag string) []string {
	if tag == "" {
		return []string{}
	}

	// 移除 "role:" 前缀
	tag = strings.TrimPrefix(tag, "role:")
	return SplitAndTrim(tag, ",")
}

// MatchPattern Pattern matching with wildcard support | 模式匹配（支持通配符*）
func MatchPattern(pattern, str string) bool {
	if pattern == WildcardChar {
		return true
	}

	if !strings.Contains(pattern, WildcardChar) {
		return pattern == str
	}

	// Simple wildcard matching | 简单的通配符匹配
	parts := strings.Split(pattern, WildcardChar)
	if len(parts) == 2 {
		prefix, suffix := parts[0], parts[1]
		if prefix != "" && !strings.HasPrefix(str, prefix) {
			return false
		}
		if suffix != "" && !strings.HasSuffix(str, suffix) {
			return false
		}
		return true
	}

	// Complex pattern with multiple wildcards | 复杂模式（多个通配符）
	pos := 0
	for i, part := range parts {
		if i == 0 && part != "" {
			if !strings.HasPrefix(str, part) {
				return false
			}
			pos += len(part)
			continue
		}
		if i == len(parts)-1 && part != "" {
			return strings.HasSuffix(str, part)
		}
		if part == "" {
			continue
		}
		idx := strings.Index(str[pos:], part)
		if idx == -1 {
			return false
		}
		pos += idx + len(part)
	}

	return true
}

// ============ Time & Duration | 时间和时长 ============

// FormatDuration Formats duration in seconds to human-readable format | 格式化时间段（秒）为人类可读格式
func FormatDuration(seconds int64) string {
	if seconds < 0 {
		return "永久"
	}

	if seconds == 0 {
		return "0秒"
	}

	if seconds < Minute {
		return fmt.Sprintf("%d秒", seconds)
	}

	if seconds < Hour {
		minutes := seconds / Minute
		return fmt.Sprintf("%d分钟", minutes)
	}

	if seconds < Day {
		hours := seconds / Hour
		return fmt.Sprintf("%d小时", hours)
	}

	if seconds < Week {
		days := seconds / Day
		return fmt.Sprintf("%d天", days)
	}

	weeks := seconds / Week
	return fmt.Sprintf("%d周", weeks)
}

// ParseDuration Parses human-readable duration to seconds | 解析人类可读的时间段为秒
func ParseDuration(duration string) int64 {
	duration = strings.ToLower(strings.TrimSpace(duration))

	if duration == "" {
		return 0
	}

	// Week | 周
	if strings.HasSuffix(duration, "w") || strings.HasSuffix(duration, "周") {
		weeks := parseInt64(strings.TrimSuffix(strings.TrimSuffix(duration, "w"), "周"))
		return weeks * Week
	}

	// Day | 天
	if strings.HasSuffix(duration, "d") || strings.HasSuffix(duration, "天") {
		days := parseInt64(strings.TrimSuffix(strings.TrimSuffix(duration, "d"), "天"))
		return days * Day
	}

	// Hour | 小时
	if strings.HasSuffix(duration, "h") || strings.HasSuffix(duration, "时") || strings.HasSuffix(duration, "小时") {
		hours := parseInt64(strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(duration, "h"), "时"), "小时"))
		return hours * Hour
	}

	// Minute | 分钟
	if strings.HasSuffix(duration, "m") || strings.HasSuffix(duration, "分") || strings.HasSuffix(duration, "分钟") {
		minutes := parseInt64(strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(duration, "m"), "分"), "分钟"))
		return minutes * Minute
	}

	// Second | 秒
	if strings.HasSuffix(duration, "s") || strings.HasSuffix(duration, "秒") {
		return parseInt64(strings.TrimSuffix(strings.TrimSuffix(duration, "s"), "秒"))
	}

	return parseInt64(duration)
}

// TimestampToTime Converts Unix timestamp to time.Time | Unix时间戳转time.Time
func TimestampToTime(timestamp int64) time.Time {
	return time.Unix(timestamp, 0)
}

// TimeToTimestamp Converts time.Time to Unix timestamp | time.Time转Unix时间戳
func TimeToTimestamp(t time.Time) int64 {
	return t.Unix()
}

// ============ Type Conversion | 类型转换 ============

// parseInt64 Parses string to int64 | 将字符串解析为int64
func parseInt64(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}

	result, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return result
}

// ToInt Converts any to int | 将any转换为int
func ToInt(v any) (int, error) {
	switch val := v.(type) {
	case int:
		return val, nil
	case int32:
		return int(val), nil
	case int64:
		return int(val), nil
	case float32:
		return int(val), nil
	case float64:
		return int(val), nil
	case string:
		return strconv.Atoi(val)
	default:
		return 0, fmt.Errorf("cannot convert %T to int", v)
	}
}

// ToInt64 Converts any to int64 | 将any转换为int64
func ToInt64(v any) (int64, error) {
	switch val := v.(type) {
	case int:
		return int64(val), nil
	case int32:
		return int64(val), nil
	case int64:
		return val, nil
	case float32:
		return int64(val), nil
	case float64:
		return int64(val), nil
	case string:
		return strconv.ParseInt(val, 10, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to int64", v)
	}
}

// ToString Converts any to string | 将any转换为string
func ToString(v any) string {
	if v == nil {
		return ""
	}

	switch val := v.(type) {
	case string:
		return val
	case []byte:
		return string(val)
	case int, int8, int16, int32, int64:
		return fmt.Sprintf("%d", val)
	case uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", val)
	case float32, float64:
		return fmt.Sprintf("%v", val)
	case bool:
		return strconv.FormatBool(val)
	default:
		return fmt.Sprintf("%v", val)
	}
}

// ToBool Converts any to bool | 将any转换为bool
func ToBool(v any) (bool, error) {
	switch val := v.(type) {
	case bool:
		return val, nil
	case string:
		return strconv.ParseBool(val)
	case int, int8, int16, int32, int64:
		return val != 0, nil
	default:
		return false, fmt.Errorf("cannot convert %T to bool", v)
	}
}

// ToBytes Converts any to bytes | 将any转换为字节
func ToBytes(value any) ([]byte, error) {
	switch v := value.(type) {
	case string:
		return []byte(v), nil
	case []byte:
		return v, nil
	case byte:
		return []byte{v}, nil
	case rune:
		return []byte(string(v)), nil
	default:
		return nil, fmt.Errorf("unsupported type: %T", value)
	}
}

// ============ Hash & Encoding | 哈希和编码 ============

// SHA256Hash Generates SHA256 hash of string | 生成字符串的SHA256哈希
func SHA256Hash(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])
}

// Base64Encode Encodes string to base64 | Base64编码
func Base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// Base64Decode Decodes base64 string | Base64解码
func Base64Decode(s string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Base64URLEncode Encodes string to URL-safe base64 | URL安全的Base64编码
func Base64URLEncode(s string) string {
	return base64.URLEncoding.EncodeToString([]byte(s))
}

// Base64URLDecode Decodes URL-safe base64 string | URL安全的Base64解码
func Base64URLDecode(s string) (string, error) {
	data, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ============ Validation | 验证 ============

// IsAlphanumeric Checks if string contains only alphanumeric characters | 检查是否只包含字母数字
func IsAlphanumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// IsNumeric Checks if string contains only numbers | 检查是否只包含数字
func IsNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// HasLength Checks if string length is within range | 检查字符串长度是否在范围内
func HasLength(s string, min, max int) bool {
	length := len(s)
	return length >= min && length <= max
}

// ============ Slice Helpers | 切片辅助 ============

// InSlice Checks if value exists in slice | 检查值是否存在于切片中
func InSlice[T comparable](slice []T, val T) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

// UniqueSlice Removes duplicates from slice | 去除切片中的重复元素
func UniqueSlice[T comparable](slice []T) []T {
	seen := make(map[T]bool, len(slice))
	result := make([]T, 0, len(slice))
	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

// GetCtxValue Returns the value for the given key in the context as a string or the defaultValue if the value is not of type string | 从上下文中获取指定key的值，如果值不是字符串则返回默认值
func GetCtxValue(ctx context.Context, valueKey string, defaultValue ...string) string {
	val := ctx.Value(valueKey) // 从上下文中获取值 | Retrieve the value from the context

	// Check if the value is a non-empty string | 检查值是否是非空字符串
	if v, ok := val.(string); ok && v != "" {
		return v // If it's a non-empty string, return it | 如果是非空字符串，返回该值
	}

	// If defaultValue is provided, return it, otherwise return an empty string | 如果提供了默认值，返回默认值，否则返回空字符串
	if len(defaultValue) > 0 {
		return defaultValue[0]
	}

	// Otherwise, return an empty string | 否则返回空字符串
	return ""
}
