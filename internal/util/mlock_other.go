// +build !windows

package util

import (
	"golang.org/x/sys/unix"
)

// MlockBytes locks all entries in the given byte slice buf to memory.
func MlockBytes(buf []byte) {
	unix.Mlock(buf) // ignore errors
}

// MunlockBytes unlocks all entries in the given byte slice buf from memory.
func MunlockBytes(buf []byte) {
	unix.Munlock(buf) // ignore errors
}
