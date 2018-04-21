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
