package main

import (
	"os"

	"github.com/drksbr/ProxyWebSock/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
