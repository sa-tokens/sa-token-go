package main

import (
	"context"
	"fmt"
	"time"

	"github.com/click33/sa-token-go/core/builder"
	"github.com/click33/sa-token-go/core/listener"
	"github.com/click33/sa-token-go/storage/memory"
	"github.com/click33/sa-token-go/stputil"
)

func main() {
	fmt.Println("=== Sa-Token-Go Event Listener Example ===\n")

	ctx := context.Background()

	// 1. Simple function listener
	mgr := builder.NewBuilder().
		SetStorage(memory.NewStorage()).
		TokenName("Authorization").
		Timeout(300).
		MaxRefresh(150).
		Build()

	mgr.RegisterFunc(listener.EventLogin, func(data *listener.EventData) {
		fmt.Printf("[LOGIN] User %s logged in with token %s\n", data.LoginID, data.Token[:20]+"...")
	})

	// 2. Logout listener
	mgr.RegisterFunc(listener.EventLogout, func(data *listener.EventData) {
		fmt.Printf("[LOGOUT] User %s logged out\n", data.LoginID)
	})

	// 3. Kickout listener
	mgr.RegisterFunc(listener.EventKickout, func(data *listener.EventData) {
		fmt.Printf("[KICKOUT] User %s was forcibly logged out\n", data.LoginID)
	})

	// 4. High-priority synchronous listener
	auditListenerID := mgr.RegisterWithConfig(listener.EventLogin,
		listener.ListenerFunc(func(data *listener.EventData) {
			fmt.Printf("[AUDIT] Login audit - User: %s, Time: %d\n",
				data.LoginID, data.Timestamp)
		}),
		listener.ListenerConfig{
			Async:    false, // Synchronous
			Priority: 100,   // High priority
			ID:       "audit-logger",
		},
	)

	// 5. Wildcard listener (all events)
	mgr.RegisterFunc(listener.EventAll, func(data *listener.EventData) {
		fmt.Printf("[ALL EVENTS] %s\n", data.String())
	})

	eventMgr := mgr.GetEventManager()

	// 6. Custom panic handler
	eventMgr.SetPanicHandler(func(event listener.Event, data *listener.EventData, recovered interface{}) {
		fmt.Printf("[PANIC RECOVERED] Event: %s, Error: %v\n", event, recovered)
	})

	// Initialize Sa-Token
	stputil.SetManager(mgr)

	fmt.Println("\n--- Triggering Events ---\n")

	// Trigger login event
	token1, _ := stputil.Login(ctx, 1000)
	time.Sleep(100 * time.Millisecond) // Wait for async listeners

	token2, _ := stputil.Login(ctx, 2000)
	time.Sleep(100 * time.Millisecond)

	// Trigger logout event
	stputil.Logout(ctx, 1000)
	time.Sleep(100 * time.Millisecond)

	// Trigger kickout event
	stputil.Kickout(ctx, 2000)
	time.Sleep(100 * time.Millisecond)

	// Wait for all async listeners to complete
	mgr.WaitEvents()

	fmt.Println("\n--- Listener Statistics ---")
	fmt.Printf("Total listeners: %d\n", eventMgr.Count())
	fmt.Printf("Login listeners: %d\n", eventMgr.CountForEvent(listener.EventLogin))
	fmt.Printf("Logout listeners: %d\n", eventMgr.CountForEvent(listener.EventLogout))

	// Unregister a listener
	fmt.Println("\n--- Unregistering audit logger ---")
	if mgr.Unregister(auditListenerID) {
		fmt.Println("Audit logger unregistered successfully")
	}

	fmt.Printf("Remaining listeners: %d\n", eventMgr.Count())

	// Disable certain events
	fmt.Println("\n--- Disabling kickout events ---")
	eventMgr.DisableEvent(listener.EventKickout)

	fmt.Println("\n--- Testing event disable (this should not trigger kickout listener) ---")
	stputil.Login(ctx, 3000)
	stputil.Kickout(ctx, 3000)
	time.Sleep(100 * time.Millisecond)

	// Re-enable all events
	eventMgr.EnableEvent()

	fmt.Println("\n=== Example Complete ===")

	// Cleanup
	fmt.Println("\nTokens:")
	fmt.Printf("Token 1: %s\n", token1)
	fmt.Printf("Token 2: %s\n", token2)
}
