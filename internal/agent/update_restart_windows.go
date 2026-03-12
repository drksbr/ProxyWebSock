//go:build windows

package agent

import "errors"

func selfUpdateSupported() bool {
	return false
}

func swapExecutable(currentPath, stagedPath string) error {
	return errors.New("self-update is not supported on windows")
}

func restartExecutable(currentPath string) error {
	return errors.New("self-update is not supported on windows")
}
