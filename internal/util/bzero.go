// Package util provides security utilities for sensitive memory handling,
// including memory locking (mlock) and secure zeroing (bzero) of byte slices
// and structs containing cryptographic key material.
package util

import (
	"fmt"
	"reflect"
)

// BzeroBytes sets all entries in the given byte slice buf to zero.
func BzeroBytes(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

type byteFunc func([]byte)

func structIterator(strct any, bf byteFunc) {
	s := reflect.ValueOf(strct).Elem()
	for i := 0; i < s.NumField(); i++ {
		f := s.Field(i)
		switch k := f.Kind(); k {
		case reflect.Array:
			BzeroBytes(f.Slice(0, f.Len()).Bytes())
		case reflect.Slice:
			BzeroBytes(f.Bytes())
		default:
			panic(fmt.Sprintf("bzero: cannot zero %s", k))
		}
	}
}

// BzeroStruct sets all entries in the given struct pointer strct to zero.
//
// IMPORTANT: The struct definition must only contain exported arrays or slices
// of byte type. If the struct contains any other field types (integers, strings,
// nested structs, etc.), this function will panic. This is by design to prevent
// silent failures when zeroing sensitive cryptographic material.
//
// Example valid struct:
//
//	type Key struct {
//	    Data   [32]byte  // OK: byte array
//	    Salt   []byte    // OK: byte slice
//	}
func BzeroStruct(strct any) {
	structIterator(strct, BzeroBytes)
}
