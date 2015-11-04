// Copyright (c) 2015 Frank Braun <frank@cryptogroup.net>
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// +build !windows

package bzero

import (
	"syscall"
)

func mlock(buf []byte) {
	syscall.Mlock(buf) // ignore errors
}

func munlock(buf []byte) {
	syscall.Munlock(buf) // ignore errors
}
