module github.com/drksbr/ProxyWebSock

go 1.22.0

toolchain go1.22.7

require (
	github.com/google/uuid v1.6.0
	github.com/gorilla/websocket v1.5.3
	github.com/prometheus/client_golang v1.20.4
	github.com/spf13/cobra v1.10.1
	golang.org/x/crypto v0.29.0
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.55.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	golang.org/x/net v0.29.0 // indirect
	golang.org/x/sys v0.27.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
)

replace (
	golang.org/x/crypto => golang.org/x/crypto v0.29.0
	golang.org/x/net => golang.org/x/net v0.29.0
	golang.org/x/sys => golang.org/x/sys v0.27.0
	golang.org/x/text => golang.org/x/text v0.21.0
)
