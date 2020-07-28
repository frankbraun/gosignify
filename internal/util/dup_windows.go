package util

import (
	"golang.org/x/sys/windows"
)

// Dup creates a copy of the file descriptor fd and returns it.
func Dup(fd uintptr) (uintptr, error) {
	p, err := windows.GetCurrentProcess()
	if err != nil {
		return 0, err
	}
	var h windows.Handle
	err = windows.DuplicateHandle(p, windows.Handle(fd), p, &h, 0, true,
		windows.DUPLICATE_SAME_ACCESS)
	if err != nil {
		return 0, err
	}
	return uintptr(h), nil
}
