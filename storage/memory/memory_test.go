package memory

import (
	"context"
	"testing"
	"time"
)

func TestMemoryStorage_SetAndGet(t *testing.T) {
	storage := NewStorage()
	defer storage.Close()

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
		_, err := storage.Get(ctx, "non_existent")
		if err == nil {
			t.Error("Expected error for non-existent key, got nil")
		}
	})
}

func TestMemoryStorage_SetKeepTTL(t *testing.T) {
	storage := NewStorage()
	defer storage.Close()

	ctx := context.Background()

	t.Run("SetKeepTTL for non-existent key", func(t *testing.T) {
		err := storage.SetKeepTTL(ctx, "non_existent_key", "value")
		if err == nil {
			t.Error("Expected error for non-existent key, got nil")
		}
	})

	t.Run("SetKeepTTL preserves TTL", func(t *testing.T) {
		key := "test_key"
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
	})
}

func TestMemoryStorage_Delete(t *testing.T) {
	storage := NewStorage()
	defer storage.Close()

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
		keys := []string{"key1", "key2", "key3"}
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
}

func TestMemoryStorage_GetAndDelete(t *testing.T) {
	storage := NewStorage()
	defer storage.Close()

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
		_, err := storage.GetAndDelete(ctx, "non_existent")
		if err == nil {
			t.Error("Expected error for non-existent key, got nil")
		}
	})
}

func TestMemoryStorage_Exists(t *testing.T) {
	storage := NewStorage()
	defer storage.Close()

	ctx := context.Background()

	t.Run("Exists for existing key", func(t *testing.T) {
		key := "exists_key"
		storage.Set(ctx, key, "value", 0)

		if !storage.Exists(ctx, key) {
			t.Error("Key should exist")
		}
	})

	t.Run("Exists for non-existent key", func(t *testing.T) {
		if storage.Exists(ctx, "non_existent") {
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

func TestMemoryStorage_Keys(t *testing.T) {
	storage := NewStorage()
	defer storage.Close()

	ctx := context.Background()

	// 设置测试数据
	testData := map[string]string{
		"user:1:token": "token1",
		"user:2:token": "token2",
		"user:1:role":  "admin",
		"session:abc":  "data1",
		"session:xyz":  "data2",
		"product:100":  "item",
		"product:200":  "item",
		"product:300":  "item",
		"expired:key":  "value",
	}

	for key, value := range testData {
		storage.Set(ctx, key, value, 0)
	}

	// 设置一个过期的键
	storage.Set(ctx, "expired:test", "value", 1*time.Second)
	time.Sleep(2 * time.Second)

	t.Run("Match all keys with *", func(t *testing.T) {
		keys, err := storage.Keys(ctx, "*")
		if err != nil {
			t.Fatalf("Failed to get keys: %v", err)
		}
		// 应该至少有9个键（不包括过期的）
		if len(keys) < len(testData) {
			t.Errorf("Expected at least %d keys, got %d", len(testData), len(keys))
		}
	})

	t.Run("Match prefix pattern user:*", func(t *testing.T) {
		keys, err := storage.Keys(ctx, "user:*")
		if err != nil {
			t.Fatalf("Failed to get keys: %v", err)
		}
		if len(keys) != 3 {
			t.Errorf("Expected 3 keys, got %d", len(keys))
		}
	})

	t.Run("Match pattern user:*:token", func(t *testing.T) {
		keys, err := storage.Keys(ctx, "user:*:token")
		if err != nil {
			t.Fatalf("Failed to get keys: %v", err)
		}
		if len(keys) != 2 {
			t.Errorf("Expected 2 keys, got %d", len(keys))
		}
	})

	t.Run("Match suffix pattern *:token", func(t *testing.T) {
		keys, err := storage.Keys(ctx, "*:token")
		if err != nil {
			t.Fatalf("Failed to get keys: %v", err)
		}
		if len(keys) != 2 {
			t.Errorf("Expected 2 keys, got %d", len(keys))
		}
	})

	t.Run("Match exact key", func(t *testing.T) {
		keys, err := storage.Keys(ctx, "user:1:token")
		if err != nil {
			t.Fatalf("Failed to get keys: %v", err)
		}
		if len(keys) != 1 {
			t.Errorf("Expected 1 key, got %d", len(keys))
		}
	})

	t.Run("Match product:* pattern", func(t *testing.T) {
		keys, err := storage.Keys(ctx, "product:*")
		if err != nil {
			t.Fatalf("Failed to get keys: %v", err)
		}
		if len(keys) != 3 {
			t.Errorf("Expected 3 keys, got %d", len(keys))
		}
	})
}

func TestMemoryStorage_Expire(t *testing.T) {
	storage := NewStorage()
	defer storage.Close()

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
		err := storage.Expire(ctx, "non_existent", 1*time.Second)
		if err == nil {
			t.Error("Expected error for non-existent key, got nil")
		}
	})

	t.Run("Expire with negative duration deletes key", func(t *testing.T) {
		key := "delete_via_expire"
		storage.Set(ctx, key, "value", 0)

		err := storage.Expire(ctx, key, -1*time.Second)
		if err != nil {
			t.Fatalf("Failed to expire key: %v", err)
		}

		if storage.Exists(ctx, key) {
			t.Error("Key should be deleted")
		}
	})
}

func TestMemoryStorage_TTL(t *testing.T) {
	storage := NewStorage()
	defer storage.Close()

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
	})

	t.Run("TTL for key without expiration", func(t *testing.T) {
		key := "no_ttl_key"
		storage.Set(ctx, key, "value", 0)

		ttl, err := storage.TTL(ctx, key)
		if err != nil {
			t.Fatalf("Failed to get TTL: %v", err)
		}

		if ttl != -1*time.Second {
			t.Errorf("Expected TTL -1s (no expiration), got %v", ttl)
		}
	})

	t.Run("TTL for non-existent key", func(t *testing.T) {
		ttl, err := storage.TTL(ctx, "non_existent")
		if err == nil {
			t.Error("Expected error for non-existent key, got nil")
		}
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
			// 过期键可能已被清理，这是正常的
			if ttl != -2*time.Second {
				t.Errorf("Expected TTL -2s for expired key, got %v", ttl)
			}
		}
	})
}

func TestMemoryStorage_Clear(t *testing.T) {
	storage := NewStorage()
	defer storage.Close()

	ctx := context.Background()

	// 设置多个键
	storage.Set(ctx, "key1", "value1", 0)
	storage.Set(ctx, "key2", "value2", 0)
	storage.Set(ctx, "key3", "value3", 0)

	err := storage.Clear(ctx)
	if err != nil {
		t.Fatalf("Failed to clear storage: %v", err)
	}

	// 验证所有键都被删除
	if storage.Exists(ctx, "key1") || storage.Exists(ctx, "key2") || storage.Exists(ctx, "key3") {
		t.Error("All keys should be deleted after Clear")
	}

	keys, _ := storage.Keys(ctx, "*")
	if len(keys) != 0 {
		t.Errorf("Expected 0 keys after Clear, got %d", len(keys))
	}
}

func TestMemoryStorage_Ping(t *testing.T) {
	storage := NewStorage()
	defer storage.Close()

	ctx := context.Background()

	err := storage.Ping(ctx)
	if err != nil {
		t.Fatalf("Ping should succeed: %v", err)
	}
}

func TestMemoryStorage_Close(t *testing.T) {
	storage := NewStorage()

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

	// 关闭后 Ping 应该失败
	err = storage.Ping(ctx)
	if err == nil {
		t.Error("Ping should fail after close")
	}

	// 重复关闭应该不报错
	err = storage.Close()
	if err != nil {
		t.Errorf("Second close should not return error: %v", err)
	}
}

func TestMemoryStorage_Cleanup(t *testing.T) {
	// 使用较短的清理间隔创建存储
	storage := NewStorageWithCleanupInterval(500 * time.Millisecond)
	defer storage.Close()

	ctx := context.Background()

	// 设置多个短期过期的键
	for i := 0; i < 10; i++ {
		key := "cleanup_key_" + string(rune(i))
		storage.Set(ctx, key, "value", 1*time.Second)
	}

	// 验证键存在
	keys, _ := storage.Keys(ctx, "cleanup_key_*")
	if len(keys) == 0 {
		t.Error("Keys should exist before expiration")
	}

	// 等待过期和清理
	time.Sleep(2 * time.Second)

	// 验证过期键被清理
	keys, _ = storage.Keys(ctx, "cleanup_key_*")
	if len(keys) != 0 {
		t.Errorf("Expected 0 keys after cleanup, got %d", len(keys))
	}
}

func TestMemoryStorage_ConcurrentAccess(t *testing.T) {
	storage := NewStorage()
	defer storage.Close()

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
