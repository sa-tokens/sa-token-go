// @Author daixk 2025/12/26 15:17:00
package slog

// Package slog provides an async logging implementation for sa-token-go.
//
// Features:
//   - Async write with buffered queue (non-blocking)
//   - Log rotation by size and time
//   - Auto cleanup of expired backup files
//   - Runtime config modification (level, prefix, stdout)
//   - Thread-safe design with proper locking
//
// TODO: Future enhancements | 未来增强计划:
//   - [ ] Structured logging with JSON format output | 结构化日志（JSON 格式输出）
//   - [ ] Sampling and rate limiting mechanism | 日志采样与限流机制
//   - [ ] Trace/Span ID support for distributed tracing | 分布式链路追踪 trace/span ID 支持
//   - [ ] Log aggregation hooks (e.g., send to ELK, Loki) | 日志聚合钩子（如发送到 ELK、Loki）
//   - [ ] Context-aware logging with context.Context | 支持 context.Context 的上下文日志
