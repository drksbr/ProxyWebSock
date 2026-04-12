//go:build windows

package agent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func selfUpdateSupported() bool {
	return true
}

func swapExecutable(currentPath, stagedPath string) error {
	nextPath := stagedExecutablePath(currentPath)
	_ = os.Remove(nextPath)
	return os.Rename(stagedPath, nextPath)
}

func restartExecutable(currentPath string) error {
	nextPath := stagedExecutablePath(currentPath)
	if _, err := os.Stat(nextPath); err != nil {
		return fmt.Errorf("resolve staged executable: %w", err)
	}

	scriptPath := filepath.Join(os.TempDir(), fmt.Sprintf("intratun-update-%d.cmd", os.Getpid()))
	script := windowsUpdateScript(currentPath, nextPath, os.Args[1:])
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		return fmt.Errorf("write windows update script: %w", err)
	}

	cmd := exec.Command("cmd.exe", "/C", scriptPath)
	cmd.Dir = filepath.Dir(currentPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start windows update helper: %w", err)
	}

	os.Exit(0)
	return nil
}

func stagedExecutablePath(currentPath string) string {
	ext := filepath.Ext(currentPath)
	base := strings.TrimSuffix(currentPath, ext)
	return base + ".next" + ext
}

func windowsUpdateScript(currentPath, nextPath string, args []string) string {
	backupPath := currentPath + ".old"
	quotedArgs := make([]string, 0, len(args))
	for _, arg := range args {
		escaped := syscall.EscapeArg(arg)
		escaped = strings.ReplaceAll(escaped, "%", "%%")
		quotedArgs = append(quotedArgs, escaped)
	}
	argSuffix := ""
	if len(quotedArgs) > 0 {
		argSuffix = " " + strings.Join(quotedArgs, " ")
	}

	return fmt.Sprintf(`@echo off
setlocal enableextensions
set "CURRENT=%s"
set "STAGED=%s"
set "BACKUP=%s"

for /l %%%%I in (1,1,120) do (
  tasklist /FI "PID eq %d" 2>nul | find "%d" >nul
  if errorlevel 1 goto replace
  ping 127.0.0.1 -n 2 >nul
)

:replace
if exist "%%BACKUP%%" del /f /q "%%BACKUP%%" >nul 2>nul
if exist "%%CURRENT%%" move /y "%%CURRENT%%" "%%BACKUP%%" >nul 2>nul
move /y "%%STAGED%%" "%%CURRENT%%" >nul
if errorlevel 1 goto rollback
start "" /b "%%CURRENT%%"%s
ping 127.0.0.1 -n 2 >nul
if exist "%%BACKUP%%" del /f /q "%%BACKUP%%" >nul 2>nul
del /f /q "%%~f0" >nul 2>nul
exit /b 0

:rollback
if exist "%%BACKUP%%" move /y "%%BACKUP%%" "%%CURRENT%%" >nul 2>nul
del /f /q "%%~f0" >nul 2>nul
exit /b 1
`, escapeBatchValue(currentPath), escapeBatchValue(nextPath), escapeBatchValue(backupPath), os.Getpid(), os.Getpid(), argSuffix)
}

func escapeBatchValue(value string) string {
	return strings.ReplaceAll(value, "%", "%%")
}
