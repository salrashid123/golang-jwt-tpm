module main

go 1.22.0

toolchain go1.22.2

require (
	github.com/google/go-tpm v0.9.1-0.20240514145214-58e3e47cd434
	github.com/google/go-tpm-tools v0.4.4
)

require (
	github.com/foxboron/go-tpm-keyfiles v0.0.0-20240620184055-b891af1cbc88
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/salrashid123/golang-jwt-tpm v1.5.0
)

require (
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/go-configfs-tsm v0.2.2 // indirect
	github.com/google/go-sev-guest v0.11.1 // indirect
	github.com/google/go-tdx-guest v0.3.1 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.23.0 // indirect
	golang.org/x/sys v0.21.0 // indirect
	google.golang.org/protobuf v1.34.1 // indirect
)

replace github.com/salrashid123/golang-jwt-tpm => ../
