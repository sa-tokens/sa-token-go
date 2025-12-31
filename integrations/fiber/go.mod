module github.com/click33/sa-token-go/integrations/fiber

go 1.23.0

toolchain go1.24.1

require (
	github.com/click33/sa-token-go/core v0.1.7
	github.com/click33/sa-token-go/stputil v0.1.7
	github.com/gofiber/fiber/v2 v2.52.0
)

require (
	github.com/andybalholm/brotli v1.0.5 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.17.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/panjf2000/ants/v2 v2.11.3 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.51.0 // indirect
	github.com/valyala/tcplisten v1.0.0 // indirect
	golang.org/x/sync v0.16.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
)

replace github.com/click33/sa-token-go/core => ../../core
