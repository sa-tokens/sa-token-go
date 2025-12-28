package main

import (
	"fmt"
	"github.com/click33/sa-token-go/core"
	"github.com/click33/sa-token-go/examples/multi-certification/authkit"
	"github.com/click33/sa-token-go/storage/memory"
	"github.com/click33/sa-token-go/stputil"
)

func main() {
	// 注意 多认证体现需要将不同的manager的KeyPrefix设置为不同的值
	storage := memory.NewStorage()
	userManager := core.NewBuilder().
		Storage(storage).
		Timeout(6600).
		IsPrintBanner(false).
		KeyPrefix("user"). // 要唯一
		Build()

	adminManager := core.NewBuilder().
		Storage(storage).
		Timeout(3600).
		IsPrintBanner(false).
		KeyPrefix("admin"). // 要唯一
		TokenStyle(core.TokenStyleTik).
		Build()

	authkit.ADMIN = stputil.NewStpLogic(adminManager)
	authkit.USER = stputil.NewStpLogic(userManager)

	Run()
}

func Run() {
	userTokenValue, _ := authkit.USER.Login("ID1")
	adminTokenValue, _ := authkit.ADMIN.Login("ID1")
	fmt.Println("userTokenValue:", userTokenValue)
	fmt.Println("adminTokenValue:", adminTokenValue)

	_ = authkit.ADMIN.SetPermissions("ID1", []string{"admin1", "admin2"})
	_ = authkit.USER.SetPermissions("ID1", []string{"user1", "user2"})
	adminPermissions, _ := authkit.ADMIN.GetPermissions("ID1")
	userPermissions, _ := authkit.USER.GetPermissions("ID1")
	fmt.Println("admin permissions:", adminPermissions)
	fmt.Println("user permissions:", userPermissions)

	fmt.Println("admin has user1 permission:", authkit.ADMIN.HasPermission("ID1", "user1"))
	fmt.Println("admin has admin1 permission:", authkit.ADMIN.HasPermission("ID1", "admin1"))
	fmt.Println("user has admin1 permission:", authkit.USER.HasPermission("ID1", "admin1"))
	fmt.Println("user has user1 permission:", authkit.USER.HasPermission("ID1", "user1"))
}
