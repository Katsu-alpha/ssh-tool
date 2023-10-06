//go:build windows
package main

import (
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

func platformInit() {
	EnableVirtualTerminal(os.Stdout.Fd())
}

func EnableVirtualTerminal(fd uintptr) error {
	var mode uint32
	if err := syscall.GetConsoleMode(syscall.Handle(fd), &mode); err != nil {
		return err
	}
	mode |= windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING

	if err := windows.SetConsoleMode(windows.Handle(fd), mode); err != nil {
		return err
	}
	return nil
}
