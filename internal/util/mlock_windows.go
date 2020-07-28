package util

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// MlockBytes locks all entries in the given byte slice buf to memory.
func MlockBytes(buf []byte) {
	windows.VirtualLock(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf))) // ignore errors
}

// MunlockBytes unlocks all entries in the given byte slice buf from memory.
func MunlockBytes(buf []byte) {
	windows.VirtualUnlock(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf))) // ignore errors
}
