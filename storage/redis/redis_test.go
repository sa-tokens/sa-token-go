package redis

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// getTestRedisClient 获取测试用的Redis客户端
// 优先使用环境变量 REDIS_URL，否则使用默认地址
func getTestRedisClient(t *testing.T) *redis.Client {
	addr := os.Getenv("REDIS_URL")
	if addr == "" {
		addr = "192.168.19.104:6379"
	}

	client := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: "root",
		DB:       0, // 使用独立的测试DB
	})

	// 测试连接
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		t.Skipf("Redis not available at %s, skipping test: %v", addr, err)
	}

	return client
}

// cleanupTestData 清理测试数据
func cleanupTestData(t *testing.T, storage *Storage) {
	ctx := context.Background()
	if err := storage.Clear(ctx); err != nil {
		t.Logf("Warning: failed to cleanup test data: %v", err)
	}
}

func TestRedisStorage_SetAndGet(t *testing.T) {
	client := getTestRedisClient(t)
	storage := NewStorageFromClient(client)
	defer storage.Close()
	defer cleanupTestData(t, storage)

	ctx := context.Background()

	t.Run("Set and Get basic value", func(t *testing.T) {
		key := "test_key"
		value := "test_value"

		err := storage.Set(ctx, key, value, 0)
		if err != nil {
			t.Fatalf("Failed to set key: %v", err)
		}

		got, err := storage.Get(ctx, key)
		if err != nil {
			t.Fatalf("Failed to get key: %v", err)
		}

		if got != value {
			t.Errorf("Expected value %q, got %q", value, got)
		}

		// 清理
		storage.Delete(ctx, key)
	})

	t.Run("Set with expiration", func(t *testing.T) {
		key := "expire_key"
		value := "expire_value"

		err := storage.Set(ctx, key, value, 2*time.Second)
		if err != nil {
			t.Fatalf("Failed to set key: %v", err)
		}

		// 立即获取应该成功
		got, err := storage.Get(ctx, key)
		if err != nil {
			t.Fatalf("Failed to get key: %v", err)
		}
		if got != value {
			t.Errorf("Expected value %q, got %q", value, got)
		}

		// 等待过期
		time.Sleep(3 * time.Second)

		// 过期后获取应该失败
		_, err = storage.Get(ctx, key)
		if err == nil {
			t.Error("Expected error for expired key, got nil")
		}
	})

	t.Run("Get non-existent key", func(t *testing.T) {
		_, err := storage.Get(ctx, "non_existent_key_12345")
		if err == nil {
			t.Error("Expected error for non-existent key, got nil")
		}
	})
}

func TestRedisStorage_SetKeepTTL(t *testing.T) {
	client := getTestRedisClient(t)
	storage := NewStorageFromClient(client)
	defer storage.Close()
	defer cleanupTestData(t, storage)

	ctx := context.Background()

	t.Run("SetKeepTTL for non-existent key", func(t *testing.T) {
		err := storage.SetKeepTTL(ctx, "non_existent_key_999", "value")
		if err == nil {
			t.Error("Expected error for non-existent key, got nil")
		}
	})

	t.Run("SetKeepTTL preserves TTL", func(t *testing.T) {
		key := "test_key_keepttl"
		originalValue := "original_value"
		newValue := "new_value"
		ttl := 10 * time.Second

		// 设置初始值和TTL
		err := storage.Set(ctx, key, originalValue, ttl)
		if err != nil {
			t.Fatalf("Failed to set key: %v", err)
		}

		// 获取原始TTL
		originalTTL, err := storage.TTL(ctx, key)
		if err != nil {
			t.Fatalf("Failed to get TTL: %v", err)
		}

		// 等待1秒
		time.Sleep(1 * time.Second)

		// 使用SetKeepTTL更新值
		err = storage.SetKeepTTL(ctx, key, newValue)
		if err != nil {
			t.Fatalf("SetKeepTTL failed: %v", err)
		}

		// 验证值已更新
		value, err := storage.Get(ctx, key)
		if err != nil {
			t.Fatalf("Failed to get value: %v", err)
		}
		if value != newValue {
			t.Errorf("Expected value %q, got %q", newValue, value)
		}

		// 验证TTL保持相对不变（允许误差）
		newTTL, err := storage.TTL(ctx, key)
		if err != nil {
			t.Fatalf("Failed to get TTL after update: %v", err)
		}

		ttlDiff := originalTTL - newTTL
		if ttlDiff < 0 {
			ttlDiff = -ttlDiff
		}
		if ttlDiff > 2*time.Second {
			t.Errorf("TTL changed significantly. Original: %v, New: %v, Diff: %v", originalTTL, newTTL, ttlDiff)
		}

		// 清理
		storage.Delete(ctx, key)
	})
}

func TestRedisStorage_Delete(t *testing.T) {
	client := getTestRedisClient(t)
	storage := NewStorageFromClient(client)
	defer storage.Close()
	defer cleanupTestData(t, storage)

	ctx := context.Background()

	t.Run("Delete single key", func(t *testing.T) {
		key := "delete_key"
		value := "delete_value"

		storage.Set(ctx, key, value, 0)

		err := storage.Delete(ctx, key)
		if err != nil {
			t.Fatalf("Failed to delete key: %v", err)
		}

		exists := storage.Exists(ctx, key)
		if exists {
			t.Error("Key should not exist after deletion")
		}
	})

	t.Run("Delete multiple keys", func(t *testing.T) {
		keys := []string{"del_key1", "del_key2", "del_key3"}
		for _, key := range keys {
			storage.Set(ctx, key, "value", 0)
		}

		err := storage.Delete(ctx, keys...)
		if err != nil {
			t.Fatalf("Failed to delete keys: %v", err)
		}

		for _, key := range keys {
			if storage.Exists(ctx, key) {
				t.Errorf("Key %s should not exist after deletion", key)
			}
		}
	})

	t.Run("Delete empty keys", func(t *testing.T) {
		err := storage.Delete(ctx)
		if err != nil {
			t.Errorf("Delete with no keys should not return error: %v", err)
		}
	})
}

func TestRedisStorage_GetAndDelete(t *testing.T) {
	client := getTestRedisClient(t)
	storage := NewStorageFromClient(client)
	defer storage.Close()
	defer cleanupTestData(t, storage)

	ctx := context.Background()

	t.Run("GetAndDelete existing key", func(t *testing.T) {
		key := "getdel_key"
		value := "getdel_value"

		storage.Set(ctx, key, value, 0)

		got, err := storage.GetAndDelete(ctx, key)
		if err != nil {
			t.Fatalf("GetAndDelete failed: %v", err)
		}

		if got != value {
			t.Errorf("Expected value %q, got %q", value, got)
		}

		// 键应该已被删除
		if storage.Exists(ctx, key) {
			t.Error("Key should not exist after GetAndDelete")
		}
	})

	t.Run("GetAndDelete non-existent key", func(t *testing.T) {
		_, err := storage.GetAndDelete(ctx, "non_existent_getdel")
		if err == nil {
			t.Error("Expected error for non-existent key, got nil")
		}
	})
}

func TestRedisStorage_Exists(t *testing.T) {
	client := getTestRedisClient(t)
	storage := NewStorageFromClient(client)
	defer storage.Close()
	defer cleanupTestData(t, storage)

	ctx := context.Background()

	t.Run("Exists for existing key", func(t *testing.T) {
		key := "exists_key"
		storage.Set(ctx, key, "value", 0)

		if !storage.Exists(ctx, key) {
			t.Error("Key should exist")
		}

		// 清理
		storage.Delete(ctx, key)
	})

	t.Run("Exists for non-existent key", func(t *testing.T) {
		if storage.Exists(ctx, "non_existent_exists") {
			t.Error("Key should not exist")
		}
	})

	t.Run("Exists for expired key", func(t *testing.T) {
		key := "expire_exists_key"
		storage.Set(ctx, key, "value", 1*time.Second)

		if !storage.Exists(ctx, key) {
			t.Error("Key should exist before expiration")
		}

		time.Sleep(2 * time.Second)

		if storage.Exists(ctx, key) {
			t.Error("Key should not exist after expiration")
		}
	})
}

func TestRedisStorage_Keys(t *testing.T) {
	client := getTestRedisClient(t)
	storage := NewStorageFromClient(client)
	defer storage.Close()
	defer cleanupTestData(t, storage)

	ctx := context.Background()

	// 设置测试数据
	testData := map[string]string{
		"test:user:1:token": "token1",
		"test:user:2:token": "token2",
		"test:user:1:role":  "admin",
		"test:session:abc":  "data1",
		"test:session:xyz":  "data2",
		"test:product:100":  "item",
		"test:product:200":  "item",
		"test:product:300":  "item",
	}

	for key, value := range testData {
		storage.Set(ctx, key, value, 0)
	}

	t.Run("Match all test keys with test:*", func(t *testing.T) {
		keys, err := storage.Keys(ctx, "test:*")
		if err != nil {
			t.Fatalf("Failed to get keys: %v", err)
		}
		if len(keys) != len(testData) {
			t.Errorf("Expected %d keys, got %d", len(testData), len(keys))
		}
	})

	t.Run("Match prefix pattern test:user:*", func(t *testing.T) {
		keys, err := storage.Keys(ctx, "test:user:*")
		if err != nil {
			t.Fatalf("Failed to get keys: %v", err)
		}
		if len(keys) != 3 {
			t.Errorf("Expected 3 keys, got %d", len(keys))
		}
	})

	t.Run("Match pattern test:user:*:token", func(t *testing.T) {
		keys, err := storage.Keys(ctx, "test:user:*:token")
		if err != nil {
			t.Fatalf("Failed to get keys: %v", err)
		}
		if len(keys) != 2 {
			t.Errorf("Expected 2 keys, got %d", len(keys))
		}
	})

	t.Run("Match exact key", func(t *testing.T) {
		keys, err := storage.Keys(ctx, "test:user:1:token")
		if err != nil {
			t.Fatalf("Failed to get keys: %v", err)
		}
		if len(keys) != 1 {
			t.Errorf("Expected 1 key, got %d", len(keys))
		}
	})

	t.Run("Match product:* pattern", func(t *testing.T) {
		keys, err := storage.Keys(ctx, "test:product:*")
		if err != nil {
			t.Fatalf("Failed to get keys: %v", err)
		}
		if len(keys) != 3 {
			t.Errorf("Expected 3 keys, got %d", len(keys))
		}
	})
}

func TestRedisStorage_Expire(t *testing.T) {
	client := getTestRedisClient(t)
	storage := NewStorageFromClient(client)
	defer storage.Close()
	defer cleanupTestData(t, storage)

	ctx := context.Background()

	t.Run("Set expiration on existing key", func(t *testing.T) {
		key := "expire_test"
		storage.Set(ctx, key, "value", 0)

		err := storage.Expire(ctx, key, 2*time.Second)
		if err != nil {
			t.Fatalf("Failed to set expiration: %v", err)
		}

		// 立即检查应该存在
		if !storage.Exists(ctx, key) {
			t.Error("Key should exist")
		}

		// 等待过期
		time.Sleep(3 * time.Second)

		// 过期后应该不存在
		if storage.Exists(ctx, key) {
			t.Error("Key should not exist after expiration")
		}
	})

	t.Run("Expire non-existent key", func(t *testing.T) {
		// Redis的EXPIRE命令对不存在的键会返回0，但不会报错
		// 这里只是确保不会崩溃
		err := storage.Expire(ctx, "non_existent_expire", 1*time.Second)
		if err != nil {
			t.Logf("Expire on non-existent key returned error (expected): %v", err)
		}
	})
}

func TestRedisStorage_TTL(t *testing.T) {
	client := getTestRedisClient(t)
	storage := NewStorageFromClient(client)
	defer storage.Close()
	defer cleanupTestData(t, storage)

	ctx := context.Background()

	t.Run("TTL for key with expiration", func(t *testing.T) {
		key := "ttl_key"
		storage.Set(ctx, key, "value", 10*time.Second)

		ttl, err := storage.TTL(ctx, key)
		if err != nil {
			t.Fatalf("Failed to get TTL: %v", err)
		}

		if ttl <= 0 || ttl > 10*time.Second {
			t.Errorf("Expected TTL between 0 and 10s, got %v", ttl)
		}

		// 清理
		storage.Delete(ctx, key)
	})

	t.Run("TTL for key without expiration", func(t *testing.T) {
		key := "no_ttl_key"
		storage.Set(ctx, key, "value", 0)

		ttl, err := storage.TTL(ctx, key)
		if err != nil {
			t.Fatalf("Failed to get TTL: %v", err)
		}

		// Redis返回-1表示永不过期
		if ttl != -1*time.Second {
			t.Errorf("Expected TTL -1s (no expiration), got %v", ttl)
		}

		// 清理
		storage.Delete(ctx, key)
	})

	t.Run("TTL for non-existent key", func(t *testing.T) {
		ttl, err := storage.TTL(ctx, "non_existent_ttl")
		if err != nil {
			t.Fatalf("Failed to get TTL: %v", err)
		}

		// Redis返回-2表示键不存在
		if ttl != -2*time.Second {
			t.Errorf("Expected TTL -2s (not found), got %v", ttl)
		}
	})

	t.Run("TTL for expired key", func(t *testing.T) {
		key := "expired_ttl_key"
		storage.Set(ctx, key, "value", 1*time.Second)

		time.Sleep(2 * time.Second)

		ttl, err := storage.TTL(ctx, key)
		if err != nil {
			t.Fatalf("Failed to get TTL: %v", err)
		}

		// 已过期的键应该返回-2
		if ttl != -2*time.Second {
			t.Errorf("Expected TTL -2s for expired key, got %v", ttl)
		}
	})
}

func TestRedisStorage_Clear(t *testing.T) {
	client := getTestRedisClient(t)
	storage := NewStorageFromClient(client)
	defer storage.Close()

	ctx := context.Background()

	// 设置多个键
	storage.Set(ctx, "clear_key1", "value1", 0)
	storage.Set(ctx, "clear_key2", "value2", 0)
	storage.Set(ctx, "clear_key3", "value3", 0)

	err := storage.Clear(ctx)
	if err != nil {
		t.Fatalf("Failed to clear storage: %v", err)
	}

	// 验证所有键都被删除
	if storage.Exists(ctx, "clear_key1") || storage.Exists(ctx, "clear_key2") || storage.Exists(ctx, "clear_key3") {
		t.Error("All keys should be deleted after Clear")
	}
}

func TestRedisStorage_Ping(t *testing.T) {
	client := getTestRedisClient(t)
	storage := NewStorageFromClient(client)
	defer storage.Close()

	ctx := context.Background()

	err := storage.Ping(ctx)
	if err != nil {
		t.Fatalf("Ping should succeed: %v", err)
	}
}

func TestRedisStorage_Close(t *testing.T) {
	client := getTestRedisClient(t)
	storage := NewStorageFromClient(client)

	ctx := context.Background()

	// 关闭前应该正常工作
	err := storage.Ping(ctx)
	if err != nil {
		t.Fatalf("Ping should succeed before close: %v", err)
	}

	// 关闭存储
	err = storage.Close()
	if err != nil {
		t.Fatalf("Failed to close storage: %v", err)
	}

	// 关闭后操作应该失败
	err = storage.Ping(ctx)
	if err == nil {
		t.Error("Ping should fail after close")
	}
}

func TestRedisStorage_NewStorage(t *testing.T) {
	t.Run("NewStorage with valid URL", func(t *testing.T) {
		url := "redis://localhost:6379/15"
		storage, err := NewStorage(url)
		if err != nil {
			t.Skipf("Redis not available, skipping test: %v", err)
		}
		defer storage.Close()

		ctx := context.Background()
		err = storage.Ping(ctx)
		if err != nil {
			t.Fatalf("Ping should succeed: %v", err)
		}
	})

	t.Run("NewStorage with invalid URL", func(t *testing.T) {
		url := "invalid://url"
		_, err := NewStorage(url)
		if err == nil {
			t.Error("Expected error for invalid URL, got nil")
		}
	})
}

func TestRedisStorage_NewStorageFromConfig(t *testing.T) {
	t.Run("NewStorageFromConfig with valid config", func(t *testing.T) {
		cfg := &Config{
			Host:             "localhost",
			Port:             6379,
			Password:         "",
			Database:         15,
			PoolSize:         10,
			OperationTimeout: 3 * time.Second,
		}

		storage, err := NewStorageFromConfig(cfg)
		if err != nil {
			t.Skipf("Redis not available, skipping test: %v", err)
		}
		defer storage.Close()

		ctx := context.Background()
		err = storage.Ping(ctx)
		if err != nil {
			t.Fatalf("Ping should succeed: %v", err)
		}
	})

	t.Run("NewStorageFromConfig with invalid config", func(t *testing.T) {
		cfg := &Config{
			Host:     "invalid-host-12345",
			Port:     9999,
			Database: 0,
			PoolSize: 10,
		}

		_, err := NewStorageFromConfig(cfg)
		if err == nil {
			t.Error("Expected error for invalid config, got nil")
		}
	})
}

func TestRedisStorage_Builder(t *testing.T) {
	t.Run("Builder pattern", func(t *testing.T) {
		storage, err := NewBuilder().
			Host("localhost").
			Port(6379).
			Database(15).
			PoolSize(10).
			Build()

		if err != nil {
			t.Skipf("Redis not available, skipping test: %v", err)
		}
		defer storage.Close()

		ctx := context.Background()
		err = storage.Ping(ctx)
		if err != nil {
			t.Fatalf("Ping should succeed: %v", err)
		}
	})

	t.Run("Builder with password", func(t *testing.T) {
		storage, err := NewBuilder().
			Host("localhost").
			Port(6379).
			Password(""). // 测试环境通常没有密码
			Database(15).
			Build()

		if err != nil {
			t.Skipf("Redis not available, skipping test: %v", err)
		}
		defer storage.Close()

		ctx := context.Background()
		err = storage.Ping(ctx)
		if err != nil {
			t.Fatalf("Ping should succeed: %v", err)
		}
	})
}

func TestRedisStorage_GetClient(t *testing.T) {
	client := getTestRedisClient(t)
	storage := NewStorageFromClient(client)
	defer storage.Close()

	redisClient := storage.GetClient()
	if redisClient == nil {
		t.Error("GetClient should return a valid client")
	}

	// 测试使用获取的客户端
	ctx := context.Background()
	err := redisClient.Ping(ctx).Err()
	if err != nil {
		t.Fatalf("Client from GetClient should work: %v", err)
	}
}

func TestRedisStorage_ConcurrentAccess(t *testing.T) {
	client := getTestRedisClient(t)
	storage := NewStorageFromClient(client)
	defer storage.Close()
	defer cleanupTestData(t, storage)

	ctx := context.Background()

	// 并发写入
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(n int) {
			key := "concurrent_key_" + string(rune(n))
			storage.Set(ctx, key, n, 0)
			done <- true
		}(i)
	}

	// 等待所有写入完成
	for i := 0; i < 10; i++ {
		<-done
	}

	// 并发读取
	for i := 0; i < 10; i++ {
		go func(n int) {
			key := "concurrent_key_" + string(rune(n))
			storage.Get(ctx, key)
			done <- true
		}(i)
	}

	// 等待所有读取完成
	for i := 0; i < 10; i++ {
		<-done
	}

	// 并发删除
	for i := 0; i < 10; i++ {
		go func(n int) {
			key := "concurrent_key_" + string(rune(n))
			storage.Delete(ctx, key)
			done <- true
		}(i)
	}

	// 等待所有删除完成
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestConcurrentDeviceAndTokenCountEnhanced(t *testing.T) {
	client := getTestRedisClient(t)
	storage := NewStorageFromClient(client)
	defer storage.Close()
	defer cleanupTestData(t, storage)

	ctx := context.Background()
	loginId := "1"

	// 清理历史数据
	if err := storage.Clear(ctx); err != nil {
		t.Fatalf("failed to clear storage: %v", err)
	}

	// 模拟同账号不同设备的登录
	keys := []string{
		// pc 设备下多个 token
		fmt.Sprintf("satoken:auth:%s:pc:tokenA", loginId),
		fmt.Sprintf("satoken:auth:%s:pc:tokenB", loginId),
		fmt.Sprintf("satoken:auth:%s:pc:tokenC", loginId),
		fmt.Sprintf("satoken:auth:%s:pc:tokenD", loginId),
		fmt.Sprintf("satoken:auth:%s:pc:tokenE", loginId),

		// 其他设备
		fmt.Sprintf("satoken:auth:%s:mobile:token123", loginId),
		fmt.Sprintf("satoken:auth:%s:ipad:token456", loginId),
		fmt.Sprintf("satoken:auth:%s:tv:token789", loginId),
	}

	for _, key := range keys {
		if err := storage.Set(ctx, key, "dummy", 0); err != nil {
			t.Fatalf("failed to set key %s: %v", key, err)
		}
	}

	// ---------- 1. 测试同账号不同设备数 ----------
	devicePattern := fmt.Sprintf("satoken:auth:%s:*:*", loginId)
	allKeys, err := storage.Keys(ctx, devicePattern)
	if err != nil {
		t.Fatalf("failed to scan keys: %v", err)
	}

	deviceSet := map[string]struct{}{}
	for _, key := range allKeys {
		parts := strings.Split(key, ":")
		if len(parts) >= 4 {
			deviceSet[parts[3]] = struct{}{}
		}
	}

	expectedDeviceCount := 4 // pc, mobile, ipad, tv
	if len(deviceSet) != expectedDeviceCount {
		t.Errorf("Expected %d devices, got %d", expectedDeviceCount, len(deviceSet))
	} else {
		t.Logf("Device count correct: %d", len(deviceSet))
	}

	// ---------- 2. 测试同账号同设备下 token 数 ----------
	device := "pc"
	tokenPattern := fmt.Sprintf("satoken:auth:%s:%s:*", loginId, device)
	deviceKeys, err := storage.Keys(ctx, tokenPattern)
	if err != nil {
		t.Fatalf("failed to scan keys for device %s: %v", device, err)
	}

	fmt.Println(len(deviceKeys))
	fmt.Println(deviceKeys)

	expectedTokenCount := 5 // tokenA ~ tokenE
	if len(deviceKeys) != expectedTokenCount {
		t.Errorf("Expected %d tokens for device %s, got %d", expectedTokenCount, device, len(deviceKeys))
	} else {
		t.Logf("Token count for device %s correct: %d", device, len(deviceKeys))
	}
}
