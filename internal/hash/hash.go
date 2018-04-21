package hash

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
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
	return hash.Sum(make([]byte, 0, sha512.Size))
}

func shaFile(hash hash.Hash, filename string) (string, error) {
	file, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}
	_, err = hash.Write(file)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(make([]byte, 0))), nil
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
	for i := 0; i < len(files); i++ {
		hash, err := sf(files[i])
		if err != nil {
			return err
		}
		if bsdFormat {
			// BSD-style output
			fmt.Fprintf(w, "%s (%s) = %s\n", algo, files[i], hash)
		} else {
			// Linux-style output
			fmt.Fprintf(w, "%s  %s\n", files[i], hash)
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
