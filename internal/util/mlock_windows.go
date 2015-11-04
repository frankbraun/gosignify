// Copyright (c) 2015 Frank Braun <frank@cryptogroup.net>
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"syscall"
	"unsafe"
)

func mlock(buf []byte) {
	syscall.VirtualLock(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf))) // ignore errors
}

func munlock(buf []byte) {
	syscall.VirtualUnlock(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf))) // ignore errors
}
