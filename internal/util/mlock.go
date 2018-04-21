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
