package hash

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSHA512(t *testing.T) {
	input := []byte("hello world")
	result := SHA512(input)

	if len(result) != SHA512Size {
		t.Errorf("SHA512 returned %d bytes, expected %d", len(result), SHA512Size)
	}

	// Known SHA-512 hash of "hello world"
	expected := []byte{
		0x30, 0x9e, 0xcc, 0x48, 0x9c, 0x12, 0xd6, 0xeb,
		0x4c, 0xc4, 0x0f, 0x50, 0xc9, 0x02, 0xf2, 0xb4,
		0xd0, 0xed, 0x77, 0xee, 0x51, 0x1a, 0x7c, 0x7a,
		0x9b, 0xcd, 0x3c, 0xa8, 0x6d, 0x4c, 0xd8, 0x6f,
		0x98, 0x9d, 0xd3, 0x5b, 0xc5, 0xff, 0x49, 0x96,
		0x70, 0xda, 0x34, 0x25, 0x5b, 0x45, 0xb0, 0xcf,
		0xd8, 0x30, 0xe8, 0x1f, 0x60, 0x5d, 0xcf, 0x7d,
		0xc5, 0x54, 0x2e, 0x93, 0xae, 0x9c, 0xd7, 0x6f,
	}

	if !bytes.Equal(result, expected) {
		t.Errorf("SHA512 hash mismatch")
	}
}

func TestSHA512Empty(t *testing.T) {
	result := SHA512([]byte{})
	if len(result) != SHA512Size {
		t.Errorf("SHA512 of empty input returned %d bytes, expected %d", len(result), SHA512Size)
	}
}

func TestSHA256File(t *testing.T) {
	tmpdir, err := os.MkdirTemp("", "hash_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	testfile := filepath.Join(tmpdir, "test.txt")
	content := []byte("test content")
	if err := os.WriteFile(testfile, content, 0644); err != nil {
		t.Fatal(err)
	}

	hash, err := SHA256File(testfile)
	if err != nil {
		t.Fatal(err)
	}

	// SHA-256 produces 32 bytes, hex-encoded is 64 characters
	if len(hash) != SHA256Size*2 {
		t.Errorf("SHA256File returned %d chars, expected %d", len(hash), SHA256Size*2)
	}

	// Known SHA-256 hash of "test content"
	expected := "6ae8a75555209fd6c44157c0aed8016e763ff435a19cf186f76863140143ff72"
	if hash != expected {
		t.Errorf("SHA256File hash = %s, expected %s", hash, expected)
	}
}

func TestSHA512File(t *testing.T) {
	tmpdir, err := os.MkdirTemp("", "hash_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	testfile := filepath.Join(tmpdir, "test.txt")
	content := []byte("test content")
	if err := os.WriteFile(testfile, content, 0644); err != nil {
		t.Fatal(err)
	}

	hash, err := SHA512File(testfile)
	if err != nil {
		t.Fatal(err)
	}

	// SHA-512 produces 64 bytes, hex-encoded is 128 characters
	if len(hash) != SHA512Size*2 {
		t.Errorf("SHA512File returned %d chars, expected %d", len(hash), SHA512Size*2)
	}
}

func TestSHA256FileNotFound(t *testing.T) {
	_, err := SHA256File("/nonexistent/file/path")
	if err == nil {
		t.Error("SHA256File should fail for nonexistent file")
	}
}

func TestSHA512FileNotFound(t *testing.T) {
	_, err := SHA512File("/nonexistent/file/path")
	if err == nil {
		t.Error("SHA512File should fail for nonexistent file")
	}
}

func TestSHA256Sum(t *testing.T) {
	tmpdir, err := os.MkdirTemp("", "hash_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	// Create test files
	files := []string{
		filepath.Join(tmpdir, "a.txt"),
		filepath.Join(tmpdir, "b.txt"),
	}
	for i, f := range files {
		if err := os.WriteFile(f, []byte{byte(i)}, 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Test BSD format
	var buf bytes.Buffer
	if err := SHA256Sum(files, &buf, true); err != nil {
		t.Fatal(err)
	}
	output := buf.String()
	if len(output) == 0 {
		t.Error("SHA256Sum BSD format produced empty output")
	}

	// Test Linux format
	buf.Reset()
	if err := SHA256Sum(files, &buf, false); err != nil {
		t.Fatal(err)
	}
	output = buf.String()
	if len(output) == 0 {
		t.Error("SHA256Sum Linux format produced empty output")
	}
}

func TestSHA512Sum(t *testing.T) {
	tmpdir, err := os.MkdirTemp("", "hash_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	// Create test file
	testfile := filepath.Join(tmpdir, "test.txt")
	if err := os.WriteFile(testfile, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := SHA512Sum([]string{testfile}, &buf, true); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Error("SHA512Sum produced empty output")
	}
}

func TestSHASumEmptyFiles(t *testing.T) {
	var buf bytes.Buffer
	if err := SHA256Sum([]string{}, &buf, true); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Error("SHA256Sum with empty file list should produce no output")
	}
}
