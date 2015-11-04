// Copyright (c) 2015 Frank Braun <frank@cryptogroup.net>
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// +build !windows

package util

import (
	"syscall"
)

// MlockBytes locks all entries in the given byte slice buf to memory.
func MlockBytes(buf []byte) {
	syscall.Mlock(buf) // ignore errors
}

// MunlockBytes unlocks all entries in the given byte slice buf from memory.
func MunlockBytes(buf []byte) {
	syscall.Munlock(buf) // ignore errors
}
