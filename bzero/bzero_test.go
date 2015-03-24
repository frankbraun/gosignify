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
