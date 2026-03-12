//go:build !windows

package agent

import (
	"os"
	"syscall"
)

func selfUpdateSupported() bool {
	return true
}

func swapExecutable(currentPath, stagedPath string) error {
	return os.Rename(stagedPath, currentPath)
}

func restartExecutable(currentPath string) error {
	return syscall.Exec(currentPath, os.Args, os.Environ())
}
