package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "intratun",
	Short: "IntraTunnel - túnel reverso via WebSocket (Go-only, single binary)",
}

func main() {
	rootCmd.AddCommand(relayCmd)
	rootCmd.AddCommand(agentCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
