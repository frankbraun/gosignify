// Copyright (c) 2015 Frank Braun <frank@cryptogroup.net>
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bzero

import (
	"fmt"
	"reflect"
)

// Bytes sets all entries in the given byte slice buf to zero.
func Bytes(buf []byte) {
	for i := 0; i < len(buf); i++ {
		buf[i] = 0
	}
}

type byteFunc func([]byte)

func structIterator(strct interface{}, bf byteFunc) {
	s := reflect.ValueOf(strct).Elem()
	for i := 0; i < s.NumField(); i++ {
		f := s.Field(i)
		switch k := f.Kind(); k {
		case reflect.Array:
			Bytes(f.Slice(0, f.Len()).Bytes())
		case reflect.Slice:
			Bytes(f.Bytes())
		default:
			panic(fmt.Sprintf("bzero: cannot zero %s", k))
		}
	}
}

// Struct sets all entries in the given struct pointer strct to zero.
// The struct definition must only contain exported arrays or slices, otherwise
// the function panics.
func Struct(strct interface{}) {
	structIterator(strct, Bytes)
}

// Mlock locks all entries in the given struct pointer to memory.
// The struct definition must only contain exported arrays or slices, otherwise
// the function panics.
func Mlock(strct interface{}) {
	structIterator(strct, mlock)
}

// Munlock unlocks all entries in the given struct pointer from memory.
// The struct definition must only contain exported arrays or slices, otherwise
// the function panics.
func Munlock(strct interface{}) {
	structIterator(strct, munlock)
}
