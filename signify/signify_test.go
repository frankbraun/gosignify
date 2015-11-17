// Copyright (c) 2015 Frank Braun <frank@cryptogroup.net>
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package signify

import (
	"bytes"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/frankbraun/gosignify/internal/hash"
)

var longComment = `
01234567890123456789012345678901234567890123456789012345678901234567890123456789
01234567890123456789012345678901234567890123456789012345678901234567890123456789
01234567890123456789012345678901234567890123456789012345678901234567890123456789
01234567890123456789012345678901234567890123456789012345678901234567890123456789
01234567890123456789012345678901234567890123456789012345678901234567890123456789
01234567890123456789012345678901234567890123456789012345678901234567890123456789
01234567890123456789012345678901234567890123456789012345678901234567890123456789
01234567890123456789012345678901234567890123456789012345678901234567890123456789
01234567890123456789012345678901234567890123456789012345678901234567890123456789
01234567890123456789012345678901234567890123456789012345678901234567890123456789
01234567890123456789012345678901234567890123456789012345678901234567890123456789
01234567890123456789012345678901234567890123456789012345678901234567890123456789
01234567890123456789012345678901234567890123456789012345678901234567890123456789
`

func createPassfile(tmpdir string) (*os.File, error) {
	passname := filepath.Join(tmpdir, "pass.txt")
	passfile, err := os.Create(passname)
	if err != nil {
		return nil, err
	}
	if _, err := passfile.WriteString("topsecret\ntopsecret\n"); err != nil {
		return nil, err
	}
	passfile.Close()
	passfile, err = os.Open(passname)
	if err != nil {
		return nil, err
	}
	return passfile, nil
}

func createMsgfile(filename string) error {
	// generate message file
	msg := make([]byte, 4096)
	if _, err := io.ReadFull(rand.Reader, msg); err != nil {
		return err
	}
	msgfp, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer msgfp.Close()
	if _, err := msgfp.Write(msg); err != nil {
		return err
	}
	return nil
}

func TestSignify(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "signify")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	pubkey := filepath.Join(tmpdir, "key.pub")
	seckey := filepath.Join(tmpdir, "key.sec")
	msgfile := filepath.Join(tmpdir, "message.txt")
	if err := createMsgfile(msgfile); err != nil {
		t.Fatal(err)
	}
	// generate new key pair (without passphrase)
	if err := Main("signify", "-G", "-n", "-p", pubkey, "-s", seckey); err != nil {
		t.Fatal(err)
	}
	// sign something
	if err := Main("signify", "-S", "-s", seckey, "-m", msgfile); err != nil {
		t.Fatal(err)
	} // verify it
	if err := Main("signify", "-V", "-p", pubkey, "-m", msgfile); err != nil {
		t.Fatal(err)
	}
	// sign something with embedded message
	if err := Main("signify", "-S", "-e", "-s", seckey, "-m", msgfile); err != nil {
		t.Fatal(err)
	}
	// verify embedded message
	if err := Main("signify", "-V", "-e", "-q", "-p", pubkey, "-m", msgfile); err != nil {
		t.Fatal(err)
	}

	// remove key files
	if err := os.Remove(pubkey); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(seckey); err != nil {
		t.Fatal(err)
	}
	// create password file to test stdin
	passfile, err := createPassfile(tmpdir)
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = passfile
	// generate new key pair (with passphrase)
	if err := Main("signify", "-G", "-p", pubkey, "-s", seckey); err != nil {
		t.Fatal(err)
	}
	passfile.Close()
	// create password file to test stdin
	passfile, err = createPassfile(tmpdir)
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = passfile
	// sign something
	if err := Main("signify", "-S", "-s", seckey, "-m", msgfile); err != nil {
		t.Fatal(err)
	}
	passfile.Close()
	// verify it
	if err := Main("signify", "-V", "-p", pubkey, "-m", msgfile); err != nil {
		t.Fatal(err)
	}
}

func testChecksum(bsdStyle bool) error {
	tmpdir, err := ioutil.TempDir("", "signify")
	if err != nil {
		return err
	}
	//defer os.RemoveAll(tmpdir)
	// create test files
	filenames := []string{"a.txt", "b.txt", "c.txt"}
	var files []string
	for i := 0; i < len(filenames); i++ {
		files = append(files, filepath.Join(tmpdir, filenames[i]))
		if err := createMsgfile(files[i]); err != nil {
			return err
		}
	}
	// create checksum files
	chk256file := filepath.Join(tmpdir, "chk256.txt")
	chk512file := filepath.Join(tmpdir, "chk512.txt")
	chk256fp, err := os.Create(chk256file)
	if err != nil {
		return err
	}
	if err := hash.SHA256Sum(files, chk256fp, bsdStyle); err != nil {
		return err
	}
	chk256fp.Close()
	chk512fp, err := os.Create(chk512file)
	if err != nil {
		return err
	}
	if err := hash.SHA512Sum(files, chk512fp, bsdStyle); err != nil {
		return err
	}
	chk512fp.Close()
	// create key pair
	pubkey := filepath.Join(tmpdir, "key.pub")
	seckey := filepath.Join(tmpdir, "key.sec")
	sig256file := filepath.Join(tmpdir, "chk256.sig")
	sig512file := filepath.Join(tmpdir, "chk512.sig")
	// generate new key pair (without passphrase)
	if err := Main("signify", "-G", "-n", "-p", pubkey, "-s", seckey); err != nil {
		return err
	}
	// sign checksum 256 file
	if err := Main("signify", "-S", "-e", "-x", sig256file, "-s", seckey, "-m", chk256file); err != nil {
		return err
	}
	// sign checksum 512 file
	if err := Main("signify", "-S", "-e", "-x", sig512file, "-s", seckey, "-m", chk512file); err != nil {
		return err
	}
	// verify checksum 256 signature files
	if err := Main("signify", "-C", "-p", pubkey, "-x", sig256file); err != nil {
		return err
	}
	// verify checksum 512 signature files
	if err := Main("signify", "-C", "-p", pubkey, "-x", sig512file, "-q"); err != nil {
		return err
	}
	// verify checksum 256 signature files (single file)
	if err := Main("signify", "-C", "-p", pubkey, "-x", sig256file, files[0]); err != nil {
		return err
	}
	// overwrite message file
	if err := createMsgfile(files[0]); err != nil {
		return err
	}
	// verify checksum 256 signature files again (should fail)
	if err := Main("signify", "-C", "-p", pubkey, "-x", sig256file); err != flag.ErrHelp {
		return errors.New("should fail with flag.ErrHelp")
	}
	return nil
}

func TestChecksum(t *testing.T) {
	// test -C for BSD-style checksum files
	if err := testChecksum(true); err != nil {
		t.Error(err)
	}
	// test -C for Linux-style checksum files
	if err := testChecksum(false); err != nil {
		t.Error(err)
	}
}

func TestUsage(t *testing.T) {
	devNull, err := os.Create(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	os.Stderr = devNull // disable output on stderr
	// no arguments
	if err := Main(); err == nil {
		t.Error("should fail")
	}
	// without mandatory arguments
	if err := Main("signify"); err != flag.ErrHelp {
		t.Error("should fail with flag.ErrHelp")
	}
	// two main modes at the same time
	if err := Main("signify", "-G", "-S"); err != flag.ErrHelp {
		t.Error("should fail with flag.ErrHelp")
	}
	if err := Main("signify", "-C", "-G"); err != flag.ErrHelp {
		t.Error("should fail with flag.ErrHelp")
	}
	if err := Main("signify", "-C", "-V"); err != flag.ErrHelp {
		t.Error("should fail with flag.ErrHelp")
	}
	// -C missing -s
	if err := Main("signify", "-C", "-n", "-p", "key.pub"); err != flag.ErrHelp {
		t.Error("should fail with flag.ErrHelp")
	}
	// -G, missing -p
	if err := Main("signify", "-G", "-n", "-s", "key.sec"); err != flag.ErrHelp {
		t.Error("should fail with flag.ErrHelp")
	}
	// -G missing -s
	if err := Main("signify", "-G", "-n", "-p", "key.pub"); err != flag.ErrHelp {
		t.Error("should fail with flag.ErrHelp")
	}
	// -G superfluous argument
	if err := Main("signify", "-G", "-n", "-p", "key.pub", "-s", "key.sec", "arg.sup"); err != flag.ErrHelp {
		t.Error("should fail with flag.ErrHelp")
	}
	// -G unknown argument
	if err := Main("signify", "-G", "-n", "-p", "key.pub", "-s", "key.sec", "-foo"); err == nil {
		t.Error("should fail")
	}
	// -G long comment
	if err := Main("signify", "-G", "-n", "-p", "key.pub", "-s", "key.sec", "-c", longComment); err == nil {
		t.Error("should fail")
	}
	// -S missing -s
	if err := Main("signify", "-S", "-n", "-p", "key.pub"); err != flag.ErrHelp {
		t.Error("should fail with flag.ErrHelp")
	}
	// -V missing -m
	if err := Main("signify", "-V", "-n", "-p", "key.pub"); err != flag.ErrHelp {
		t.Error("should fail with flag.ErrHelp")
	}
	// -V, -m - missing -s
	if err := Main("signify", "-V", "-n", "-m", "-"); err != flag.ErrHelp {
		t.Error("should fail with flag.ErrHelp")
	}
}

func diff(fname1, fname2 string) error {
	fc1, err := ioutil.ReadFile(fname1)
	if err != nil {
		return err
	}
	fc2, err := ioutil.ReadFile(fname2)
	if err != nil {
		return err
	}
	if !bytes.Equal(fc1, fc2) {
		return fmt.Errorf("files '%s' and '%s' differ", fname1, fname2)
	}
	return nil
}

func TestOriginal(t *testing.T) {
	pubkey := filepath.Join("testdata", "regresskey.pub")
	seckey := filepath.Join("testdata", "regresskey.sec")
	orders := filepath.Join("testdata", "orders.txt")
	forgery := filepath.Join("testdata", "forgery.txt")
	test := filepath.Join("testdata", "test.sig")
	confirmorders := filepath.Join("testdata", "confirmorders")
	hsh := filepath.Join("testdata", "HASH")

	// cat $seckey | signify -S -s - -x test.sig -m $orders
	// diff -u "$orders.sig" test.sig
	stdin := os.Stdin // backup stdin
	sk, err := os.Open(seckey)
	if err != nil {
		t.Fatal(err)
	}
	defer sk.Close()
	os.Stdin = sk
	if err := Main("signify", "-S", "-s", "-", "-x", test, "-m", orders); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(test)
	os.Stdin = stdin // reset stdin
	if err := diff(orders+".sig", test); err != nil {
		t.Error(err)
	}

	// signify -V -q -p $pubkey -m $orders
	if err := Main("signify", "-V", "-q", "-p", pubkey, "-m", orders); err != nil {
		t.Error(err)
	}

	// signify -V -q -p $pubkey -m $forgery 2> /dev/null && exit 1
	if err := Main("signify", "-V", "-q", "-p", pubkey, "-m", forgery); err == nil {
		t.Error("should fail")
	}

	// signify -S -s $seckey -x confirmorders.sig -e -m $orders
	// signify -V -q -p $pubkey -e -m confirmorders
	// diff -u $orders confirmorders
	if err := Main("signify", "-S", "-s", seckey, "-x", confirmorders+".sig", "-e", "-m", orders); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(confirmorders + ".sig")
	if err := Main("signify", "-V", "-q", "-p", pubkey, "-e", "-m", confirmorders); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(confirmorders)
	if err := diff(orders, confirmorders); err != nil {
		t.Error(err)
	}

	// sha256 $pubkey $seckey > HASH
	// sha512 $orders $forgery >> HASH
	// signify -S -e -s $seckey -m HASH
	// rm HASH
	// signify -C -q -p $pubkey -x HASH.sig
	hp, err := os.Create(hsh)
	if err != nil {
		t.Fatal(err)
	}
	if err := hash.SHA256Sum([]string{pubkey, seckey}, hp, true); err != nil {
		t.Fatal(err)
	}
	if err := hash.SHA512Sum([]string{orders, forgery}, hp, true); err != nil {
		t.Fatal(err)
	}
	if err := hp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := Main("signify", "-S", "-e", "-s", seckey, "-m", hsh); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(hsh + ".sig")
	if err := os.Remove(hsh); err != nil {
		t.Fatal(err)
	}
	if err := Main("signify", "-C", "-q", "-p", pubkey, "-x", hsh+".sig"); err != nil {
		t.Error(err)
	}
}
