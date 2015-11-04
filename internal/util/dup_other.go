// Copyright (c) 2015 Frank Braun <frank@cryptogroup.net>
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// +build !windows

package util

import (
	"syscall"
)

// Dup creates a copy of the file descriptor fd and returns it.
func Dup(fd int) (int, error) {
	return syscall.Dup(fd)
}
