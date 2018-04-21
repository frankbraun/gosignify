package util

import (
	"syscall"
	"unsafe"
)

// MlockBytes locks all entries in the given byte slice buf to memory.
func MlockBytes(buf []byte) {
	syscall.VirtualLock(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf))) // ignore errors
}

// MunlockBytes unlocks all entries in the given byte slice buf from memory.
func MunlockBytes(buf []byte) {
	syscall.VirtualUnlock(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf))) // ignore errors
}
