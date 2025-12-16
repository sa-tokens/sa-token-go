# Event Listener Guide

Sa-Token-Go provides a powerful event system that allows you to hook into authentication and authorization events. This guide explains how to use event listeners effectively.

## Table of Contents

- [Overview](#overview)
- [Available Events](#available-events)
- [Basic Usage](#basic-usage)
- [Advanced Features](#advanced-features)
- [Best Practices](#best-practices)
- [Examples](#examples)

## Overview

The event system allows you to:

- **Monitor** authentication activities (login, logout, kickout)
- **Audit** permission and role checks
- **React** to session lifecycle events
- **Log** security-related operations
- **Extend** functionality without modifying core code

## Available Events

| Event | Description | When Triggered |
|-------|-------------|----------------|
| `EventLogin` | User login | When a user successfully logs in |
| `EventLogout` | User logout | When a user logs out |
| `EventKickout` | Forced logout | When a user is forcibly logged out |
| `EventDisable` | Account disabled | When an account is disabled/banned |
| `EventUntie` | Account enabled | When an account is re-enabled |
| `EventRenew` | Token renewal | When a token is automatically renewed |
| `EventCreateSession` | Session created | When a new session is created |
| `EventDestroySession` | Session destroyed | When a session is destroyed |
| `EventPermissionCheck` | Permission check | When a permission check is performed |
| `EventRoleCheck` | Role check | When a role check is performed |
| `EventAll` | Wildcard | Matches all events (use with caution) |

## Basic Usage

### 1. 创建带事件功能的 Manager

```go
import (
    "github.com/click33/sa-token-go/core"
    "github.com/click33/sa-token-go/storage/memory"
)

manager := core.NewBuilder().
    Storage(memory.NewStorage()).
    Build()

// 如需高级控制，可以获取底层事件管理器
eventMgr := manager.GetEventManager()
```

### 2. 注册简单监听器

```go
// 基于函数的监听器
manager.RegisterFunc(core.EventLogin, func(data *core.EventData) {
    fmt.Printf("User logged in: %s\n", data.LoginID)
})
```

### 3. 完整示例

```go
package main

import (
    "fmt"
    "github.com/click33/sa-token-go/core"
    "github.com/click33/sa-token-go/stputil"
    "github.com/click33/sa-token-go/storage/memory"
)

func main() {
    // Create manager with log event support
    manager := core.NewBuilder().
        Storage(memory.NewStorage()).
        Build()
    
    // Register login listener
    manager.RegisterFunc(core.EventLogin, func(data *core.EventData) {
        fmt.Printf("[LOGIN] User: %s, Token: %s, Device: %s\n", 
            data.LoginID, data.Token, data.Device)
    })
    
    // Register logout listener
    manager.RegisterFunc(core.EventLogout, func(data *core.EventData) {
        fmt.Printf("[LOGOUT] User: %s\n", data.LoginID)
    })
    
    // Initialize StpUtil
    stputil.SetManager(manager)
    
    // Perform login (will trigger event)
    token, _ := stputil.Login(1000)
    fmt.Println("Token:", token)
    
    // Perform logout (will trigger event)
    stputil.Logout(1000)
}
```

## Advanced Features

### Priority-Based Listeners

Control the execution order of listeners using priorities:

```go
// High priority listener (executes first)
manager.RegisterWithConfig(core.EventLogin, 
    core.ListenerFunc(func(data *core.EventData) {
        fmt.Println("High priority listener")
    }),
    core.ListenerConfig{
        Priority: 100,
        Async: false,
    },
)

// Low priority listener (executes later)
manager.RegisterWithConfig(core.EventLogin,
    core.ListenerFunc(func(data *core.EventData) {
        fmt.Println("Low priority listener")
    }),
    core.ListenerConfig{
        Priority: 10,
        Async: false,
    },
)
```

### Synchronous vs Asynchronous Execution

```go
// Synchronous listener (blocks until complete)
manager.RegisterWithConfig(core.EventLogin,
    core.ListenerFunc(func(data *core.EventData) {
        // Critical operation that must complete before continuing
        saveToDatabase(data)
    }),
    core.ListenerConfig{
        Async: false, // Synchronous
    },
)

// Asynchronous listener (non-blocking)
manager.RegisterWithConfig(core.EventLogin,
    core.ListenerFunc(func(data *core.EventData) {
        // Non-critical operation (logging, analytics)
        sendToAnalytics(data)
    }),
    core.ListenerConfig{
        Async: true, // Default
    },
)
```

### Unregistering Listeners

```go
// Register with a custom ID
listenerID := manager.RegisterWithConfig(core.EventLogin,
    core.ListenerFunc(func(data *core.EventData) {
        fmt.Println("Temporary listener")
    }),
    core.ListenerConfig{
        ID: "my-temp-listener",
    },
)

// Later, unregister by ID
manager.Unregister(listenerID)
```

### Wildcard Listeners

Listen to all events:

```go
// Listen to all events
manager.RegisterFunc(core.EventAll, func(data *core.EventData) {
    fmt.Printf("[%s] LoginID: %s\n", data.Event, data.LoginID)
})
```

### Custom Panic Handler

Handle panics in listeners gracefully:

```go
eventMgr.SetPanicHandler(func(event core.Event, data *core.EventData, recovered interface{}) {
    log.Printf("Listener panic: event=%s, error=%v, data=%+v", event, recovered, data)
    // Send alert, increment error counter, etc.
})
```

### Enable/Disable Events

Control which events are active:

```go
// Disable specific events
eventMgr.DisableEvent(core.EventRenew, core.EventPermissionCheck)

// Enable only specific events
eventMgr.EnableEvent(core.EventLogin, core.EventLogout, core.EventKickout)

// Enable all events
eventMgr.EnableEvent() // No arguments = enable all
```

### Wait for Async Listeners

Useful for testing or graceful shutdown:

```go
// Trigger events
stputil.Login(1000)
stputil.Login(2000)

// Wait for all async listeners to complete
manager.WaitEvents()
```

## Best Practices

### 1. Use Async for Non-Critical Operations

```go
// ✅ Good: Async for logging
manager.RegisterWithConfig(core.EventLogin,
    core.ListenerFunc(func(data *core.EventData) {
        logToFile(data) // Can be async
    }),
    core.ListenerConfig{Async: true},
)

// ❌ Avoid: Sync for slow operations
manager.RegisterWithConfig(core.EventLogin,
    core.ListenerFunc(func(data *core.EventData) {
        sendEmail(data) // Slow operation blocks login
    }),
    core.ListenerConfig{Async: false},
)
```

### 2. Keep Listeners Fast and Lightweight

```go
// ✅ Good: Quick processing
manager.RegisterFunc(core.EventLogin, func(data *core.EventData) {
    counter.Increment("login_count")
})

// ❌ Avoid: Heavy processing
manager.RegisterFunc(core.EventLogin, func(data *core.EventData) {
    processLargeDataset() // This should be in a background job
})
```

### 3. Use Priority for Order-Sensitive Operations

```go
// Validation (high priority)
manager.RegisterWithConfig(core.EventLogin,
    validationListener,
    core.ListenerConfig{Priority: 100},
)

// Logging (low priority)
manager.RegisterWithConfig(core.EventLogin,
    loggingListener,
    core.ListenerConfig{Priority: 10},
)
```

### 4. Handle Errors Gracefully

```go
manager.RegisterFunc(core.EventLogin, func(data *core.EventData) {
    defer func() {
        if r := recover(); r != nil {
            log.Printf("Listener error: %v", r)
        }
    }()
    
    // Your listener logic
    riskyOperation(data)
})
```

## Examples

### Example 1: Audit Logger

```go
type AuditLogger struct {
    file *os.File
}

func (a *AuditLogger) OnEvent(data *core.EventData) {
    entry := fmt.Sprintf("[%d] %s - User: %s, Token: %s\n",
        data.Timestamp, data.Event, data.LoginID, data.Token)
    a.file.WriteString(entry)
}

// Usage
logger := &AuditLogger{file: logFile}
manager.Register(core.EventAll, logger)
```

### Example 2: Security Monitor

```go
type SecurityMonitor struct {
    alertChan chan string
}

func (s *SecurityMonitor) OnEvent(data *core.EventData) {
    switch data.Event {
    case core.EventKickout:
        s.alertChan <- fmt.Sprintf("User %s was kicked out", data.LoginID)
    case core.EventDisable:
        s.alertChan <- fmt.Sprintf("Account %s was disabled", data.LoginID)
    }
}

// Usage
monitor := &SecurityMonitor{alertChan: make(chan string, 100)}
manager.Register(core.EventKickout, monitor)
manager.Register(core.EventDisable, monitor)
```

### Example 3: Login Counter with Redis

```go
manager.RegisterFunc(core.EventLogin, func(data *core.EventData) {
    // Increment daily login counter
    key := fmt.Sprintf("login:count:%s", time.Now().Format("2006-01-02"))
    redisClient.Incr(ctx, key)
    redisClient.Expire(ctx, key, 7*24*time.Hour)
    
    // Track unique users
    userKey := fmt.Sprintf("login:users:%s", time.Now().Format("2006-01-02"))
    redisClient.SAdd(ctx, userKey, data.LoginID)
})
```

### Example 4: Multi-Factor Authentication

```go
manager.RegisterWithConfig(core.EventLogin,
    core.ListenerFunc(func(data *core.EventData) {
        // Check if MFA is required
        if requiresMFA(data.LoginID) {
            // Store pending MFA verification
            storePendingMFA(data.LoginID, data.Token)
            
            // Send MFA code
            sendMFACode(data.LoginID)
        }
    }),
    core.ListenerConfig{
        Async:    false, // Must complete before login returns
        Priority: 100,   // High priority
    },
)
```

### Example 5: Session Analytics

```go
type SessionAnalytics struct {
    sessions map[string]time.Time
    mu       sync.RWMutex
}

func (s *SessionAnalytics) OnEvent(data *core.EventData) {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    switch data.Event {
    case core.EventCreateSession:
        s.sessions[data.LoginID] = time.Now()
    case core.EventDestroySession:
        if startTime, ok := s.sessions[data.LoginID]; ok {
            duration := time.Since(startTime)
            recordSessionDuration(data.LoginID, duration)
            delete(s.sessions, data.LoginID)
        }
    }
}

// Usage
analytics := &SessionAnalytics{sessions: make(map[string]time.Time)}
manager.Register(core.EventCreateSession, analytics)
manager.Register(core.EventDestroySession, analytics)
```

## EventData Structure

```go
type EventData struct {
    Event     Event                  // Event type (e.g., "login", "logout")
    LoginID   string                 // User login identifier
    Device    string                 // Device identifier (e.g., "web", "mobile")
    Token     string                 // Authentication token
    Extra     map[string]interface{} // Custom data (event-specific)
    Timestamp int64                  // Unix timestamp when event occurred
}
```

### Accessing Extra Data

```go
manager.RegisterFunc(core.EventLogin, func(data *core.EventData) {
    if ipAddr, ok := data.Extra["ip_address"].(string); ok {
        fmt.Printf("Login from IP: %s\n", ipAddr)
    }
    
    if userAgent, ok := data.Extra["user_agent"].(string); ok {
        fmt.Printf("User agent: %s\n", userAgent)
    }
})
```

## Thread Safety

All event manager operations are thread-safe:

```go
// Safe to call from multiple goroutines
go manager.RegisterFunc(core.EventLogin, handler1)
go manager.RegisterFunc(core.EventLogin, handler2)
go eventMgr.Trigger(&core.EventData{Event: core.EventLogin})
```

## Performance Considerations

1. **Async by default**: Most listeners should be async to avoid blocking
2. **Limit listeners**: Too many listeners can impact performance
3. **Use priorities wisely**: Only when order matters
4. **Monitor listener count**: Use `eventMgr.Count()` to track

```go
// Check listener count
totalListeners := eventMgr.Count()
loginListeners := eventMgr.CountForEvent(core.EventLogin)

fmt.Printf("Total listeners: %d, Login listeners: %d\n", 
    totalListeners, loginListeners)
```

## Related Documentation

- [Authentication Guide](authentication.md)
- [Session Management](session.md)
- [Error Handling](../api/errors.md)


