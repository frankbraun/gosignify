// +build !windows

package util

import (
	"golang.org/x/sys/unix"
)

// Dup creates a copy of the file descriptor fd and returns it.
func Dup(fd uintptr) (uintptr, error) {
	d, err := unix.Dup(int(fd))
	if err != nil {
		return 0, err
	}
	return uintptr(d), nil
}
