package log

// ILogger defines core logging methods | 核心日志输出接口
type ILogger interface {
	Print(v ...any)                 // Print general log | 普通日志打印
	Printf(format string, v ...any) // Print formatted general log | 普通日志格式化打印

	Debug(v ...any)                 // Print debug level log | 调试级别日志
	Debugf(format string, v ...any) // Print formatted debug log | 调试级别格式化日志

	Info(v ...any)                 // Print info level log | 信息级别日志
	Infof(format string, v ...any) // Print formatted info log | 信息级别格式化日志

	Warn(v ...any)                 // Print warning level log | 警告级别日志
	Warnf(format string, v ...any) // Print formatted warning log | 警告级别格式化日志

	Error(v ...any)                 // Print error level log | 错误级别日志
	Errorf(format string, v ...any) // Print formatted error log | 错误级别格式化日志
}

// LoggerControl defines configuration and lifecycle control | 日志控制接口
type LoggerControl interface {
	SetLevel(level LogLevel) // Set minimum log level | 设置最小输出级别
	SetPrefix(prefix string) // Set log prefix | 设置日志前缀
	SetStdout(enable bool)   // Enable/disable console output | 设置是否输出到终端
	Close()                  // Close current file handle | 关闭当前日志文件
}
