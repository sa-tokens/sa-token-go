// @Author daixk 2025/12/7 19:53:00
package dep

//import (
//	"errors"
//
//	codec_json "github.com/click33/sa-token-go/codec/json"
//	"github.com/click33/sa-token-go/core/adapter"
//	"github.com/click33/sa-token-go/log/nop"
//	"github.com/click33/sa-token-go/pool/ants"
//	"github.com/click33/sa-token-go/storage/memory"
//)
//
//// Dep Dependency manager containing serializer, logger, storage and pool | 依赖管理器，包含序列化器、日志器、存储适配器和协程池组件
//type Dep struct {
//	storage    adapter.Storage // Storage adapter (Redis, Memory, etc.) | 存储适配器（如 Redis、Memory）
//	serializer adapter.Codec   // Codec adapter for encoding and decoding operations | 编解码器适配器
//	logger     adapter.Log     // Log adapter for logging operations | 日志适配器
//	pool       adapter.Pool    // Async task pool component | 异步任务协程池组件
//}
//
//// NewDep Creates a new Dep instance with strict parameter checking | 创建一个 Dep 实例（严格校验参数）
//func NewDep(serializer adapter.Codec, logger adapter.Log, storage adapter.Storage, pool adapter.Pool) (*Dep, error) {
//	if serializer == nil {
//		return nil, errors.New("serializer cannot be nil") // Serializer cannot be nil | 序列化器不能为空
//	}
//	if logger == nil {
//		return nil, errors.New("logger cannot be nil") // Logger cannot be nil | 日志实现不能为空
//	}
//	if storage == nil {
//		return nil, errors.New("storage cannot be nil") // Storage cannot be nil | 存储实现不能为空
//	}
//
//	return &Dep{
//		serializer: serializer,
//		logger:     logger,
//		storage:    storage,
//		pool:       pool,
//	}, nil
//}
//
//// NewDefaultDep Creates a new Dep instance with default implementations | 创建一个使用默认实现的 Dep 实例
//func NewDefaultDep() *Dep {
//	return &Dep{
//		serializer: codec_json.NewJSONSerializer(),
//		logger:     nop.NewNopLogger(),
//		storage:    memory.NewStorage(),
//		pool:       ants.NewRenewPoolManagerWithDefaultConfig(),
//	}
//}
//
//func (d *Dep) SetSerializer(serializer adapter.Codec) {
//	if serializer == nil {
//		serializer = codec_json.NewJSONSerializer()
//	}
//	d.serializer = serializer
//}
//
//func (d *Dep) GetSerializer() adapter.Codec {
//	return d.serializer
//}
//
//func (d *Dep) ResetSerializer() {
//	d.serializer = codec_json.NewJSONSerializer()
//}
//
//func (d *Dep) SetLogger(logger adapter.Log) {
//	if logger == nil {
//		logger = nop.NewNopLogger()
//	}
//	d.logger = logger
//}
//
//func (d *Dep) GetLogger() adapter.Log {
//	return d.logger
//}
//
//func (d *Dep) ResetLogger() {
//	d.logger = nop.NewNopLogger()
//}
//
//func (d *Dep) SetStorage(storage adapter.Storage) {
//	if storage == nil {
//		storage = memory.NewStorage()
//	}
//	d.storage = storage
//}
//
//func (d *Dep) GetStorage() adapter.Storage {
//	return d.storage
//}
//
//func (d *Dep) ResetStorage() {
//	d.storage = memory.NewStorage()
//}
//
//func (d *Dep) SetPool(pool adapter.Pool) {
//	d.pool = pool // pool 允许为 nil
//}
//
//func (d *Dep) GetPool() adapter.Pool {
//	return d.pool
//}
//
//func (d *Dep) ResetPool() {
//	d.pool = nil
//}
//
//// ResetAll resets all dependencies to default | 重置所有依赖
//func (d *Dep) ResetAll() {
//	d.serializer = codec_json.NewJSONSerializer()
//	d.logger = nop.NewNopLogger()
//	d.storage = memory.NewStorage()
//	d.pool = nil
//}
//
//func (d *Dep) Logger() adapter.Log       { return d.logger }
//func (d *Dep) Storage() adapter.Storage  { return d.storage }
//func (d *Dep) Serializer() adapter.Codec { return d.serializer }
//func (d *Dep) Pool() adapter.Pool        { return d.pool }
