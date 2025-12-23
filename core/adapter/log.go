// @Author daixk 2025/12/12 10:45:00
package adapter

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
