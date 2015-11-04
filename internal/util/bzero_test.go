// Copyright (c) 2015 Frank Braun <frank@cryptogroup.net>
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestBytes(t *testing.T) {
	zero := make([]byte, 1024)
	buf := make([]byte, 1024)
	// compare new buffer
	if !bytes.Equal(buf, zero) {
		t.Error("buffers differ")
	}
	// fill buffer with random data
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		t.Fatal(err)
	}
	// zero
	Bytes(buf)
	// compare reset buffer
	if !bytes.Equal(buf, zero) {
		t.Error("buffers differ")
	}
}

type T struct {
	A [1024]byte
	B []byte
}

func TestStruct(t *testing.T) {
	zero := T{B: make([]byte, 1024)}
	strct := T{B: make([]byte, 1024)}
	// compare new structs
	if !bytes.Equal(strct.A[:], zero.A[:]) || !bytes.Equal(strct.B, zero.B) {
		t.Error("buffers differ")
	}
	// fill struct with random data
	if _, err := io.ReadFull(rand.Reader, strct.A[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(rand.Reader, strct.B); err != nil {
		t.Fatal(err)
	}
	// zero
	Struct(&strct)
	// compare resets structs
	if !bytes.Equal(strct.A[:], zero.A[:]) || !bytes.Equal(strct.B, zero.B) {
		t.Error("buffers differ")
	}
}
