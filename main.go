package main

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "intratun",
	Short: "IntraTunnel - túnel reverso via WebSocket (Go-only, single binary)",
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("[main] inicializando IntraTunnel CLI")

	rootCmd.AddCommand(relayCmd)
	rootCmd.AddCommand(agentCmd)
	log.Printf("[main] comandos registrados: %d", len(rootCmd.Commands()))

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	log.Println("[main] execução finalizada sem erros")
}
