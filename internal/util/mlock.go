// Copyright (c) 2015 Frank Braun <frank@cryptogroup.net>
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

// MlockStruct locks all entries in the given struct pointer to memory.
// The struct definition must only contain exported arrays or slices, otherwise
// the function panics.
func MlockStruct(strct interface{}) {
	structIterator(strct, MlockBytes)
}

// MunlockStruct unlocks all entries in the given struct pointer from memory.
// The struct definition must only contain exported arrays or slices, otherwise
// the function panics.
func MunlockStruct(strct interface{}) {
	structIterator(strct, MunlockBytes)
}
