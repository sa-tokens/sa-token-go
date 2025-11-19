module github.com/click33/sa-token-go/integrations/echo

go 1.23.0

toolchain go1.24.1

require (
	github.com/click33/sa-token-go/core v0.1.4
	github.com/click33/sa-token-go/stputil v0.1.4
	github.com/labstack/echo/v4 v4.11.4
)

require (
	github.com/golang-jwt/jwt/v5 v5.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/labstack/gommon v0.4.2 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/panjf2000/ants/v2 v2.11.3 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasttemplate v1.2.2 // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sync v0.16.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	golang.org/x/text v0.28.0 // indirect
)

replace github.com/click33/sa-token-go/core => ../../core
