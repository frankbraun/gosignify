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
	BzeroBytes(buf)
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
	BzeroStruct(&strct)
	// compare resets structs
	if !bytes.Equal(strct.A[:], zero.A[:]) || !bytes.Equal(strct.B, zero.B) {
		t.Error("buffers differ")
	}
}

func TestBzeroEmptyBuffer(t *testing.T) {
	// Test that BzeroBytes handles empty buffer without panic
	buf := []byte{}
	BzeroBytes(buf)

	// Test nil buffer
	var nilBuf []byte
	BzeroBytes(nilBuf)
}

func TestMlockEmptyBuffer(t *testing.T) {
	// Test that MlockBytes handles empty buffer without panic
	buf := []byte{}
	MlockBytes(buf)
	MunlockBytes(buf)

	// Test nil buffer
	var nilBuf []byte
	MlockBytes(nilBuf)
	MunlockBytes(nilBuf)
}

func TestMlockStruct(t *testing.T) {
	strct := T{B: make([]byte, 1024)}
	// Fill with random data
	if _, err := io.ReadFull(rand.Reader, strct.A[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(rand.Reader, strct.B); err != nil {
		t.Fatal(err)
	}

	// These should not panic
	MlockStruct(&strct)
	MunlockStruct(&strct)
}

func TestMlockBytes(t *testing.T) {
	buf := make([]byte, 1024)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		t.Fatal(err)
	}

	// These should not panic
	MlockBytes(buf)
	MunlockBytes(buf)
}
