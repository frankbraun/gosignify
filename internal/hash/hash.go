// Package hash provides SHA-256 and SHA-512 hashing utilities for files and buffers.
package hash

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
)

const (
	// SHA256Size is the size of a SHA-256 hash.
	SHA256Size = sha256.Size
	// SHA512Size is the size of a SHA-512 hash.
	SHA512Size = sha512.Size
)

// SHA512 computes the SHA-512 hash of the given buffer.
func SHA512(buffer []byte) []byte {
	hash := sha512.New()
	hash.Write(buffer)
	return hash.Sum(nil)
}

// shaFile computes the hash of a file and returns it as a hex-encoded string.
func shaFile(hash hash.Hash, filename string) (string, error) {
	file, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	_, err = hash.Write(file)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// SHA256File computes the SHA-256 hash of the file denoted by filename and
// returns it as a hex encoded string.
func SHA256File(filename string) (string, error) {
	return shaFile(sha256.New(), filename)
}

// SHA512File computes the SHA-512 hash of the file denoted by filename and
// returns it as a hex encoded string.
func SHA512File(filename string) (string, error) {
	return shaFile(sha512.New(), filename)
}

type shaFunc func(string) (string, error)

func shaSum(sf shaFunc, algo string, files []string, w io.Writer, bsdFormat bool) error {
	for _, file := range files {
		hash, err := sf(file)
		if err != nil {
			return err
		}
		if bsdFormat {
			// BSD-style output
			fmt.Fprintf(w, "%s (%s) = %s\n", algo, file, hash)
		} else {
			// Linux-style output
			fmt.Fprintf(w, "%s  %s\n", hash, file)
		}
	}
	return nil
}

// SHA256Sum computes the SHA-256 hash of all files and writes the result to w.
// If bsdFormat is true, output is shown in BSD-style. Linux-style otherwise.
func SHA256Sum(files []string, w io.Writer, bsdFormat bool) error {
	return shaSum(SHA256File, "SHA256", files, w, bsdFormat)
}

// SHA512Sum computes the SHA-512 hash of all files and writes the result to w.
// If bsdFormat is true, output is shown in BSD-style. Linux-style otherwise.
func SHA512Sum(files []string, w io.Writer, bsdFormat bool) error {
	return shaSum(SHA512File, "SHA512", files, w, bsdFormat)
}
