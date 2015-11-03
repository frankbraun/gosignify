// Package bcrypt_pbkdf implements OpenBSD's bcrypt_pbkdf(3)
package bcrypt_pbkdf

import (
	"crypto/sha512"
	"github.com/ebfe/bcrypt_pbkdf/blowfish"
)

//  derived from /usr/src/lib/libutil/bcrypt_pbkdf.c
/*
	$OpenBSD: bcrypt_pbkdf.c,v 1.6 2014/01/31 16:56:32 tedu Exp $

	Copyright (c) 2013 Ted Unangst <tedu@openbsd.org>

	Permission to use, copy, modify, and distribute this software for any
	purpose with or without fee is hereby granted, provided that the above
	copyright notice and this permission notice appear in all copies.

	THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
	WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
	MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
	ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
	WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
	ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
	OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

const (
	bcryptBlocks   = 8
	bcryptHashSize = 4 * bcryptBlocks
	magic          = "OxychromaticBlowfishSwatDynamite"
)

func bcryptHash(bf *blowfish.Cipher, hpass, hsalt, out []byte) {
	err := bf.InitSaltedCipher(hpass, hsalt)
	if err != nil {
		panic(err)
	}

	for i := 0; i < 64; i++ {
		blowfish.ExpandKey(hsalt, bf)
		blowfish.ExpandKey(hpass, bf)
	}

	copy(out, magic)

	for i := 0; i < 64; i++ {
		for j := 0; j < bcryptHashSize/blowfish.BlockSize; j++ {
			bf.Encrypt(out[j*blowfish.BlockSize:], out[j*blowfish.BlockSize:])
		}
	}

	for i := 0; i < len(out); i += 4 {
		out[i+0], out[i+1], out[i+2], out[i+3] = out[i+3], out[i+2], out[i+1], out[i+0]
	}
}

func bcryptPBKDF(password, salt []byte, rounds, keyLen int) []byte {
	countsalt := make([]byte, 4)
	hpass := make([]byte, sha512.Size)
	hsalt := make([]byte, sha512.Size)
	out := make([]byte, bcryptHashSize)
	tmp := make([]byte, bcryptHashSize)
	key := make([]byte, keyLen)
	cipher := &blowfish.Cipher{}

	stride := (keyLen + bcryptHashSize - 1) / bcryptHashSize
	amt := (keyLen + stride - 1) / stride

	sha := sha512.New()
	sha.Write(password)
	hpass = sha.Sum(hpass[:0])

	for count := uint32(1); keyLen > 0; count++ {
		sha.Reset()
		sha.Write(salt)
		countsalt[0] = byte(count >> 24)
		countsalt[1] = byte(count >> 16)
		countsalt[2] = byte(count >> 8)
		countsalt[3] = byte(count)
		sha.Write(countsalt)
		hsalt = sha.Sum(hsalt[:0])

		bcryptHash(cipher, hpass, hsalt, tmp)
		copy(out, tmp)

		for i := 1; i < rounds; i++ {
			sha.Reset()
			sha.Write(tmp)
			hsalt = sha.Sum(hsalt[:0])
			bcryptHash(cipher, hpass, hsalt, tmp)
			for i := range out {
				out[i] ^= tmp[i]
			}
		}

		if amt > keyLen {
			amt = keyLen
		}

		for i := 0; i < amt; i++ {
			key[i*stride+(int(count)-1)] = out[i]
		}
		keyLen -= amt
	}

	return key
}

func Key(password, salt []byte, rounds, keyLen int) []byte {
	return bcryptPBKDF(password, salt, rounds, keyLen)
}
