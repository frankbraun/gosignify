package util

import (
	"syscall"
)

// Dup creates a copy of the file descriptor fd and returns it.
func Dup(fd uintptr) (uintptr, error) {
	p, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0, err
	}
	var h syscall.Handle
	err = syscall.DuplicateHandle(p, syscall.Handle(fd), p, &h, 0, true,
		syscall.DUPLICATE_SAME_ACCESS)
	if err != nil {
		return 0, err
	}
	return uintptr(h), nil
}
