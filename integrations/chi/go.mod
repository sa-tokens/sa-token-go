module github.com/click33/sa-token-go/integrations/chi

go 1.23.0

require (
	github.com/click33/sa-token-go/core v0.1.5
	github.com/click33/sa-token-go/stputil v0.1.5
)

require (
	github.com/golang-jwt/jwt/v5 v5.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/panjf2000/ants/v2 v2.11.3 // indirect
	golang.org/x/sync v0.16.0 // indirect
)

replace (
	github.com/click33/sa-token-go/core => ../../core
	github.com/click33/sa-token-go/stputil => ../../stputil
)
