package main

import (
	"fmt"
	"os"
	"time"
	"runtime"
	"path"
	"syscall"

	"golang.org/x/sys/windows"
)

const (
	colorReset = "\033[0m"

    colorRed = "\033[31m"
    colorGreen = "\033[32m"
    colorYellow = "\033[33m"
    colorBlue = "\033[34m"
    colorPurple = "\033[35m"
    colorCyan = "\033[36m"
    colorWhite = "\033[37m"
)

const (
	debugLevel = iota
	infoLevel
	warnLevel
	errorLevel
	critLevel
)

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

type MyLogger struct {
	loglevel int
	id string
}

func NewMyLogger(loglevel int, id string) *MyLogger {
	var l MyLogger
	l.loglevel = loglevel
	l.id = id
	return &l
}

func CloneMyLogger(l *MyLogger, id string) *MyLogger {
	var clone MyLogger
	clone = *l
	clone.id = id
	return &clone
}

func printHdr() {
	fmt.Print(time.Now().Format("2006/01/02 15:04:05.000 "))
	_, file, line, ok := runtime.Caller(3)
	if ok {
		fmt.Printf("%v:%v ", path.Base(file), line)
	}
}
func (l *MyLogger) getHdr() string {
	s := time.Now().Format("2006/01/02 15:04:05.000 ") + "<" + l.id + "> "
	_, file, line, ok := runtime.Caller(3)
	if ok {
		s += fmt.Sprintf("%v:%v ", path.Base(file), line)
	}
	return s
}

func (l *MyLogger) _debug(s string) {
	if l.loglevel > debugLevel {
		return
	}
	msg := l.getHdr() + "[DBUG] " + s
	fmt.Print(colorGreen)
	fmt.Print(msg)
	fmt.Println(colorReset)

}

func (l *MyLogger) _info(s string) {
	if l.loglevel > infoLevel {
		return
	}
	msg := l.getHdr() + "[INFO] " + s
	fmt.Print(colorCyan)
	fmt.Print(msg)
	fmt.Println(colorReset)
}

func (l *MyLogger) _warn(s string) {
	if l.loglevel > warnLevel {
		return
	}
	msg := l.getHdr() + "[WARN] " + s
	fmt.Print(colorYellow)
	fmt.Print(msg)
	fmt.Println(colorReset)
}

func (l *MyLogger) _error(s string) {
	if l.loglevel > errorLevel {
		return
	}
	msg := l.getHdr() + "[ERR ] " + s
	fmt.Print(colorRed)
	fmt.Print(msg)
	fmt.Println(colorReset)
}

func (l *MyLogger) _fatal(s string) {
	msg := l.getHdr() + "[FATAL] " + s
	fmt.Print(colorPurple)
	fmt.Print(msg)
	fmt.Println(colorReset)
}

func (l *MyLogger) Debug(v ...any) {
	l._debug(fmt.Sprint(v...))
}

func (l *MyLogger) Info(v ...any) {
	l._info(fmt.Sprint(v...))
}

func (l *MyLogger) Warn(v ...any) {
	l._warn(fmt.Sprint(v...))
}

func (l *MyLogger) Error(v ...any) {
	l._error(fmt.Sprint(v...))
}

func (l *MyLogger) Fatal(v ...any) {
	l._fatal(fmt.Sprint(v...))
	os.Exit(1)
}

func (l *MyLogger) Debugf(f string, v ...any) {
	l._debug(fmt.Sprintf(f, v...))
}

func (l *MyLogger) Infof(f string, v ...any) {
	l._info(fmt.Sprintf(f, v...))
}

func (l *MyLogger) Warnf(f string, v ...any) {
	l._warn(fmt.Sprintf(f, v...))
}

func (l *MyLogger) Errorf(f string, v ...any) {
	l._error(fmt.Sprintf(f, v...))
}



