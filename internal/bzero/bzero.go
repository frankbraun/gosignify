package bzero

/*
 * Copyright (c) 2015 Frank Braun <frank@cryptogroup.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

import (
	"fmt"
	"reflect"
	"syscall"
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

func mlock(buf []byte) {
	syscall.Mlock(buf) // ignore mlock errors
}

// Mlock locks all entries in the given struct pointer to memory.
// The struct definition must only contain exported arrays or slices, otherwise
// the function panics.
func Mlock(strct interface{}) {
	structIterator(strct, mlock)
}

func munlock(buf []byte) {
	syscall.Munlock(buf) // ignore munlock errors
}

// Munlock unlocks all entries in the given struct pointer from memory.
// The struct definition must only contain exported arrays or slices, otherwise
// the function panics.
func Munlock(strct interface{}) {
	structIterator(strct, munlock)
}
