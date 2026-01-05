//go:build !windows

package util

import (
	"os"
	"testing"
)

func TestDup(t *testing.T) {
	// Create a temporary file
	f, err := os.CreateTemp("", "dup_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	// Write some data
	testData := []byte("hello, world")
	if _, err := f.Write(testData); err != nil {
		t.Fatal(err)
	}

	// Duplicate the file descriptor
	dupFd, err := Dup(f.Fd())
	if err != nil {
		t.Fatalf("Dup failed: %v", err)
	}

	// Create a new file from the duplicated descriptor
	dupFile := os.NewFile(dupFd, "dup")
	defer dupFile.Close()

	// Seek to beginning and read from the duplicated descriptor
	if _, err := dupFile.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(testData))
	n, err := dupFile.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(testData) {
		t.Errorf("expected to read %d bytes, got %d", len(testData), n)
	}
	if string(buf) != string(testData) {
		t.Errorf("expected %q, got %q", testData, buf)
	}
}

func TestDupStdout(t *testing.T) {
	// Test duplicating stdout (common use case in signify)
	dupFd, err := Dup(os.Stdout.Fd())
	if err != nil {
		t.Fatalf("Dup stdout failed: %v", err)
	}
	// Close the duplicated fd
	dupFile := os.NewFile(dupFd, "stdout_dup")
	if err := dupFile.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestDupStdin(t *testing.T) {
	// Test duplicating stdin (common use case in signify)
	dupFd, err := Dup(os.Stdin.Fd())
	if err != nil {
		t.Fatalf("Dup stdin failed: %v", err)
	}
	// Close the duplicated fd
	dupFile := os.NewFile(dupFd, "stdin_dup")
	if err := dupFile.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
}
