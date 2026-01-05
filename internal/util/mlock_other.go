//go:build !windows

package util

import (
	"golang.org/x/sys/unix"
)

// MlockBytes locks all entries in the given byte slice buf to memory.
// This prevents the memory from being swapped to disk, protecting sensitive
// cryptographic material.
//
// Errors are intentionally ignored because mlock may fail due to:
//   - Insufficient privileges (EPERM) - common in containers or restricted environments
//   - Resource limits (ENOMEM) - process has hit RLIMIT_MEMLOCK
//
// The operation is best-effort: if mlock fails, the program continues
// but sensitive data may be swapped to disk.
func MlockBytes(buf []byte) {
	if len(buf) == 0 {
		return
	}
	unix.Mlock(buf)
}

// MunlockBytes unlocks all entries in the given byte slice buf from memory.
// Errors are intentionally ignored as munlock failures are non-critical.
func MunlockBytes(buf []byte) {
	if len(buf) == 0 {
		return
	}
	unix.Munlock(buf)
}
