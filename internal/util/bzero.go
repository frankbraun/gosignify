package util

import (
	"fmt"
	"reflect"
)

// BzeroBytes sets all entries in the given byte slice buf to zero.
func BzeroBytes(buf []byte) {
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
			BzeroBytes(f.Slice(0, f.Len()).Bytes())
		case reflect.Slice:
			BzeroBytes(f.Bytes())
		default:
			panic(fmt.Sprintf("bzero: cannot zero %s", k))
		}
	}
}

// BzeroStruct sets all entries in the given struct pointer strct to zero.
// The struct definition must only contain exported arrays or slices, otherwise
// the function panics.
func BzeroStruct(strct interface{}) {
	structIterator(strct, BzeroBytes)
}
