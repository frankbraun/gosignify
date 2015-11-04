// Copyright (c) 2015 Frank Braun <frank@cryptogroup.net>
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// +build !windows

package util

import (
	"syscall"
)

// Dup creates a copy of the file descriptor fd and returns it.
func Dup(fd uintptr) (uintptr, error) {
	d, err := syscall.Dup(int(fd))
	if err != nil {
		return 0, err
	}
	return uintptr(d), nil
}
