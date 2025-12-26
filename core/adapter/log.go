// @Author daixk 2025/12/12 10:45:00
package adapter

// LogLevel defines log severity level | 日志级别定义
type LogLevel int

const (
	LogLevelDebug LogLevel = iota + 1 // Debug level | 调试级别
	LogLevelInfo                      // Info level | 信息级别
	LogLevelWarn                      // Warn level | 警告级别
	LogLevelError                     // Error level | 错误级别（最高）
)

// String returns the string representation of log level | 返回日志级别的字符串表示
func (l LogLevel) String() string {
	switch l {
	case LogLevelDebug:
		return "DEBUG"
	case LogLevelInfo:
		return "INFO"
	case LogLevelWarn:
		return "WARN"
	case LogLevelError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// Log defines logging behavior abstraction | 日志行为抽象接口
type Log interface {
	Print(v ...any)                 // Print log without level | 无级别日志输出
	Printf(format string, v ...any) // Print formatted log without level | 无级别格式化日志输出

	Debug(v ...any)                 // Print debug level log | 输出调试级别日志
	Debugf(format string, v ...any) // Print formatted debug level log | 输出调试级别格式化日志

	Info(v ...any)                 // Print info level log | 输出信息级别日志
	Infof(format string, v ...any) // Print formatted info level log | 输出信息级别格式化日志

	Warn(v ...any)                 // Print warn level log | 输出警告级别日志
	Warnf(format string, v ...any) // Print formatted warn level log | 输出警告级别格式化日志

	Error(v ...any)                 // Print error level log | 输出错误级别日志
	Errorf(format string, v ...any) // Print formatted error level log | 输出错误级别格式化日志
}

// LogControl defines runtime control methods for loggers | 日志运行时控制接口
type LogControl interface {
	Log

	// ---- Lifecycle | 生命周期 ----
	Close() // Close the logger and release resources | 关闭日志并释放资源
	Flush() // Flush buffered logs to output | 刷新缓冲区

	// ---- Runtime Config | 运行时配置 ----
	SetLevel(level LogLevel) // Update minimum log level | 动态更新日志级别
	SetPrefix(prefix string) // Update log prefix | 动态更新日志前缀
	SetStdout(enable bool)   // Enable/disable stdout output | 开关控制台输出

	// ---- Status Query | 状态查询 ----
	LogPath() string   // Get log directory path | 获取日志目录
	DropCount() uint64 // Get dropped log count (queue full) | 获取丢弃的日志数量
}
