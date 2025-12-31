module github.com/click33/sa-token-go/stputil

go 1.23.0

require github.com/click33/sa-token-go/core v0.1.7

require (
	github.com/golang-jwt/jwt/v5 v5.3.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/panjf2000/ants/v2 v2.11.3 // indirect
	golang.org/x/sync v0.19.0 // indirect
)

replace github.com/click33/sa-token-go/core => ../core
