package signify

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
	"flag"
	"io/ioutil"
	"os"
	"path"
	"testing"
)

func TestSignify(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "signify")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	// generate new key pair
	if err := Main("signify", "-G", "-n", "-p", path.Join(tmpdir, "pubkey"), "-s", path.Join(tmpdir, "seckey")); err != nil {
		t.Fatal(err)
	}
	// sign something
	if err := Main("signify", "-S", "-s", path.Join(tmpdir, "seckey"), "-m", path.Join(tmpdir, "pubkey")); err != nil {
		t.Fatal(err)
	}
}

func TestUsage(t *testing.T) {
	devNull, err := os.Create(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()
	os.Stderr = devNull // disable output on stderr
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
}
