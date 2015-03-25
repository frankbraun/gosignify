package hash

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
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
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
