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

/*
   This code is heavily based on C code from OpenBSD in src/usr.bin/signify/ which is
   Copyright (c) 2013 Ted Unangst <tedu@openbsd.org>
   covered by the same license as above.

   "If I have seen further it is by standing on the shoulders of giants."
   -- Isaac Newton
*/

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"syscall"

	"github.com/agl/ed25519"
	"github.com/ebfe/bcrypt_pbkdf"
)

const (
	SIGBYTES    = ed25519.SignatureSize
	SECRETBYTES = ed25519.PrivateKeySize
	PUBLICBYTES = ed25519.PublicKeySize

	PKALG     = "Ed"
	KDFALG    = "BK"
	KEYNUMLEN = 8

	COMMENTHDR    = "untrusted comment: "
	COMMENTHDRLEN = 19
	COMMENTMAXLEN = 1024
	VERIFYWITH    = "verify with "
)

type enckey struct {
	Pkalg     [2]byte
	Kdfalg    [2]byte
	Kdfrounds [4]byte
	Salt      [16]byte
	Checksum  [8]byte
	Keynum    [KEYNUMLEN]byte
	Seckey    [SECRETBYTES]byte
}

type pubkey struct {
	Pkalg  [2]byte
	Keynum [KEYNUMLEN]byte
	Pubkey [PUBLICBYTES]byte
}

type sig struct {
	Pkalg  [2]byte
	Keynum [KEYNUMLEN]byte
	Sig    [SIGBYTES]byte
}

var (
	argv0 string
	fs    *flag.FlagSet
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage:")
	fmt.Fprintf(os.Stderr, "\t%s -C [-q] -p pubkey -x sigfile [file ...]\n", argv0)
	fmt.Fprintf(os.Stderr, "\t%s -G [-n] [-c comment] -p pubkey -s seckey\n", argv0)
	fmt.Fprintf(os.Stderr, "\t%s -S [-e] [-x sigfile] -s seckey -m message\n", argv0)
	fmt.Fprintf(os.Stderr, "\t%s -V [-eq] [-x sigfile] -p pubkey -m message\n", argv0)
	fs.PrintDefaults()
}

func bzero(buf []byte) {
	for i := 0; i < len(buf); i++ {
		buf[i] = 0
	}
}

func (enckey *enckey) bzero() {
	bzero(enckey.Pkalg[:])
	bzero(enckey.Kdfalg[:])
	bzero(enckey.Kdfrounds[:])
	bzero(enckey.Salt[:])
	bzero(enckey.Checksum[:])
	bzero(enckey.Keynum[:])
	bzero(enckey.Seckey[:])
}

func xopen(fname string, oflags, mode int) (*os.File, error) {
	var (
		fd  *os.File
		err error
	)
	if fname == "-" {
		if oflags&os.O_WRONLY > 0 {
			fdsc, err := syscall.Dup(int(os.Stdout.Fd()))
			if err != nil {
				return nil, err
			}
			fd = os.NewFile(uintptr(fdsc), "stdout")
		} else {
			fdsc, err := syscall.Dup(int(os.Stdin.Fd()))
			if err != nil {
				return nil, err
			}
			fd = os.NewFile(uintptr(fdsc), "stdin")
		}
	} else {
		fd, err = os.OpenFile(fname, oflags, os.FileMode(mode))
		if err != nil {
			return nil, err
		}
	}
	fi, err := fd.Stat()
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("not a valid file: %s", fname)
	}
	return fd, nil
}

func parseb64file(filename string, b64 []byte) (string, []byte, []byte, error) {
	lines := strings.SplitAfterN(string(b64), "\n", 3)
	if len(lines) < 2 || !strings.HasPrefix(lines[0], COMMENTHDR) {
		return "", nil, nil, fmt.Errorf("invalid comment in %s; must start with '%s'", filename, COMMENTHDR)
	}
	comment := strings.TrimSuffix(lines[0], "\n")
	if len(comment) >= COMMENTMAXLEN {
		return "", nil, nil, errors.New("comment too long") // for compatibility
	}
	if !strings.HasSuffix(lines[1], "\n") {
		return "", nil, nil, fmt.Errorf("missing new line after base64 in %s", filename)
	}
	enc := strings.TrimSuffix(lines[1], "\n")
	buf, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", nil, nil, fmt.Errorf("invalid base64 encoding in %s", filename)
	}
	if len(buf) < 2 || string(buf[:2]) != PKALG {
		return "", nil, nil, fmt.Errorf("unsupported file %s", filename)
	}
	var msg []byte
	if len(lines) == 3 {
		msg = []byte(lines[2])
	}
	return comment, buf, msg, nil
}

func readb64file(filename string) (string, []byte, error) {
	fd, err := xopen(filename, os.O_RDONLY, 0)
	if err != nil {
		return "", nil, err
	}
	defer fd.Close()
	b64, err := ioutil.ReadAll(fd)
	if err != nil {
		return "", nil, err
	}
	buf, comment, _, err := parseb64file(filename, b64)
	if err != nil {
		return "", nil, err
	}
	bzero(b64)
	return buf, comment, nil
}

func readmsg(filename string) ([]byte, error) {
	fd, err := xopen(filename, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	msg, err := ioutil.ReadAll(fd)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func writeb64file(filename, comment string, data interface{}, msg []byte, oflags, mode int) error {
	fd, err := xopen(filename, os.O_CREATE|oflags|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer fd.Close()
	header := fmt.Sprintf("%s%s\n", COMMENTHDR, comment)
	if len(header) >= COMMENTMAXLEN {
		return errors.New("comment too long") // for compatibility
	}
	if _, err := fd.WriteString(header); err != nil {
		return err
	}
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, data); err != nil {
		return err
	}
	b64 := base64.StdEncoding.EncodeToString(buf.Bytes())
	if _, err := fd.WriteString(b64 + "\n"); err != nil {
		return err
	}
	if len(msg) > 0 {
		if _, err := fd.Write(msg); err != nil {
			return err
		}
	}
	return nil
}

func kdf(salt []byte, rounds int, confirm bool, key []byte) error {
	if rounds == 0 {
		// key is already initalized to zero, not need to do it again
		return nil
	}

	// read passphrase from stdin
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("passphrase: ")
	pass, err := reader.ReadString('\n')
	if err != nil {
		return err
	}

	// confirm passphrase, if necessary
	if confirm {
		fmt.Println("confirm passphrase: ")
		pass2, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if pass != pass2 {
			return errors.New("passwords don't match")
		}
	}

	pass = strings.TrimSuffix(pass, "\n")
	k := bcrypt_pbkdf.Key([]byte(pass), salt, rounds, len(key))
	copy(key, k)

	return nil
}

func generate(pubkeyfile, seckeyfile string, rounds int, comment string) error {
	var (
		pubkey pubkey
		enckey enckey
		xorkey [SECRETBYTES]byte
		keynum [KEYNUMLEN]byte
	)

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	copy(pubkey.Pubkey[:], publicKey[:])
	copy(enckey.Seckey[:], privateKey[:])
	if _, err := io.ReadFull(rand.Reader, keynum[:]); err != nil {
		return err
	}

	hash := sha512.New()
	hash.Write(privateKey[:])
	digest := hash.Sum(make([]byte, 0, sha512.Size))

	copy(enckey.Pkalg[:], []byte(PKALG))
	copy(enckey.Kdfalg[:], []byte(KDFALG))
	binary.BigEndian.PutUint32(enckey.Kdfrounds[:], uint32(rounds))
	copy(enckey.Keynum[:], keynum[:])
	if _, err := io.ReadFull(rand.Reader, enckey.Salt[:]); err != nil {
		return err
	}
	if err := kdf(enckey.Salt[:], rounds, true, xorkey[:]); err != nil {
		return err
	}
	copy(enckey.Checksum[:], digest[:])
	for i := 0; i < len(enckey.Seckey); i++ {
		enckey.Seckey[i] ^= xorkey[i]
	}
	bzero(digest)
	bzero(xorkey[:])

	commentbuf := fmt.Sprintf("%s secret key", comment)
	if len(commentbuf) >= COMMENTMAXLEN {
		return errors.New("comment too long") // for compatibility
	}
	if err := writeb64file(seckeyfile, commentbuf, &enckey, nil, os.O_EXCL, 0600); err != nil {
		return err
	}
	enckey.bzero()

	copy(pubkey.Pkalg[:], []byte(PKALG))
	copy(pubkey.Keynum[:], keynum[:])
	commentbuf = fmt.Sprintf("%s public key", comment)
	if len(commentbuf) >= COMMENTMAXLEN {
		return errors.New("comment too long") // for compatibility
	}
	if err := writeb64file(pubkeyfile, commentbuf, &pubkey, nil, os.O_EXCL, 0666); err != nil {
		return err
	}

	return nil
}

func sign(seckeyfile, msgfile, sigfile string, embedded bool) error {
	var (
		sig        sig
		enckey     enckey
		xorkey     [SECRETBYTES]byte
		sigcomment string
	)

	comment, buf, err := readb64file(seckeyfile)
	if err != nil {
		return err
	}
	if err := binary.Read(bytes.NewReader(buf), binary.BigEndian, &enckey); err != nil {
		return err
	}

	if string(enckey.Kdfalg[:]) != KDFALG {
		return errors.New("unsupported KDF")
	}
	rounds := binary.BigEndian.Uint32(enckey.Kdfrounds[:])

	if err := kdf(enckey.Salt[:], int(rounds), false, xorkey[:]); err != nil {
		return err
	}
	for i := 0; i < len(enckey.Seckey); i++ {
		enckey.Seckey[i] ^= xorkey[i]
	}
	bzero(xorkey[:])
	hash := sha512.New()
	hash.Write(enckey.Seckey[:])
	digest := hash.Sum(make([]byte, 0, sha512.Size))
	if !bytes.Equal(enckey.Checksum[:], digest[:8]) {
		return errors.New("incorrect passphrase")
	}
	bzero(digest)

	msg, err := readmsg(msgfile)
	if err != nil {
		return err
	}

	sig.Sig = *ed25519.Sign(&enckey.Seckey, msg)
	sig.Keynum = enckey.Keynum
	enckey.bzero()

	copy(sig.Pkalg[:], []byte(PKALG))
	if strings.HasSuffix(seckeyfile, ".sec") {
		prefix := strings.TrimSuffix(seckeyfile, ".sec")
		sigcomment = fmt.Sprintf("%s%s.pub", VERIFYWITH, prefix)
		if len(sigcomment) >= COMMENTMAXLEN {
			return errors.New("comment too long") // for compatibility
		}
	} else {
		sigcomment = fmt.Sprintf("signature from %s", comment)
		if len(sigcomment) >= COMMENTMAXLEN {
			return errors.New("comment too long") // for compatibility
		}
	}

	if embedded {
		if err := writeb64file(sigfile, sigcomment, &sig, msg, os.O_TRUNC, 0666); err != nil {
			return err
		}
	} else {
		if err := writeb64file(sigfile, sigcomment, &sig, nil, os.O_TRUNC, 0666); err != nil {
			return err
		}
	}

	return nil
}

func verifymsg(pubkey *pubkey, msg []byte, sig *sig, quiet bool) error {
	if !bytes.Equal(pubkey.Keynum[:], sig.Keynum[:]) {
		return errors.New("verification failed: checked against wrong key")
	}
	if !ed25519.Verify(&pubkey.Pubkey, msg, &sig.Sig) {
		return errors.New("signature verification failed")
	}
	if !quiet {
		fmt.Println("Signature Verified")
	}
	return nil
}

func readpubkey(pubkeyfile, sigcomment string) ([]byte, error) {
	safepath := "/etc/signify/" // TODO: make this portable!

	if pubkeyfile == "" {
		if strings.Contains(sigcomment, VERIFYWITH) {
			tokens := strings.SplitAfterN(sigcomment, VERIFYWITH, 2)
			pubkeyfile = tokens[1]
			if !strings.HasPrefix(pubkeyfile, safepath) ||
				strings.Contains(pubkeyfile, "/../") { // TODO: make this portable!
				return nil, fmt.Errorf("untrusted path %s", pubkeyfile)
			}
		} else {
			fmt.Fprintln(os.Stderr, "must specify pubkey")
			usage()
			return nil, flag.ErrHelp
		}
	}
	_, buf, err := readb64file(pubkeyfile)
	if err != nil {
		return nil, err
	}
	return buf, err
}

func verifysimple(pubkeyfile, msgfile, sigfile string, quiet bool) error {
	var (
		sig    sig
		pubkey pubkey
	)

	msg, err := readmsg(msgfile)
	if err != nil {
		return err
	}

	sigcomment, buf, err := readb64file(sigfile)
	if err != nil {
		return err
	}
	if err := binary.Read(bytes.NewReader(buf), binary.BigEndian, &sig); err != nil {
		return err
	}
	buf, err = readpubkey(pubkeyfile, sigcomment)
	if err := binary.Read(bytes.NewReader(buf), binary.BigEndian, &pubkey); err != nil {
		return err
	}

	return verifymsg(&pubkey, msg, &sig, quiet)
}

func verifyembedded(pubkeyfile, sigfile string, quiet bool) ([]byte, error) {
	var (
		sig    sig
		pubkey pubkey
	)

	msg, err := readmsg(sigfile)
	if err != nil {
		return nil, err
	}

	sigcomment, buf, msg, err := parseb64file(sigfile, msg)
	if err != nil {
		return nil, err
	}
	if err := binary.Read(bytes.NewReader(buf), binary.BigEndian, &sig); err != nil {
		return nil, err
	}
	buf, err = readpubkey(pubkeyfile, sigcomment)
	if err := binary.Read(bytes.NewReader(buf), binary.BigEndian, &pubkey); err != nil {
		return nil, err
	}

	return msg, verifymsg(&pubkey, msg, &sig, quiet)
}

func verify(pubkeyfile, msgfile, sigfile string, embedded, quiet bool) error {
	if embedded {
		msg, err := verifyembedded(pubkeyfile, sigfile, quiet)
		if err != nil {
			return err
		}
		fd, err := xopen(msgfile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0666)
		if err != nil {
			return err
		}
		defer fd.Close()
		if _, err := fd.Write(msg); err != nil {
			return err
		}
		return nil
	}
	return verifysimple(pubkeyfile, msgfile, sigfile, quiet)
}

func check(pubkeyfile, sigfile string, quiet bool) error {
	// TODO
	return errors.New("not implemented")
}

// Main calls the signify tool with the given args. args[0] is mandatory and
// should be the command name. If a wrong combination of options was used but no
// further error should be displayed, then flag.ErrHelp is returned.
func Main(args ...string) error {
	const (
		NONE = iota
		CHECK
		GENERATE
		SIGN
		VERIFY
	)
	verb := NONE
	rounds := 42

	if len(args) == 0 {
		return errors.New("at least one argument is mandatory")
	}

	argv0 = args[0]
	fs = flag.NewFlagSet(argv0, flag.ContinueOnError)
	fs.Usage = usage
	CFLAG := fs.Bool("C", false, "Verify a signed checksum list, and then verify the checksum for each file. If no files are specified, all of them are checked. sigfile should be the signed output of sha256(1).")
	GFlag := fs.Bool("G", false, "Generate a new key pair.")
	SFlag := fs.Bool("S", false, "Sign the specified message file and create a signature.")
	VFlag := fs.Bool("V", false, "Verify the message and signature match.")
	comment := fs.String("c", "signify", "Specify the comment to be added during key generation.")
	eFlag := fs.Bool("e", false, "When signing, embed the message after the signature. When verifying, extract the message from the signature. (This requires that the signature was created using -e and creates a new message file as output.)")
	msgfile := fs.String("m", "", "When signing, the file containing the message to sign. When verifying, the file containing the message to verify. When verifying with -e, the file to create.")
	nFlag := fs.Bool("n", false, "Do not ask for a passphrase during key generation. Otherwise, signify will prompt the user for a passphrase to protect the secret key.")
	pubkey := fs.String("p", "", "Public key produced by -G, and used by -V to check a signature.")
	qFlag := fs.Bool("q", false, "Quiet mode. Suppress informational output.")
	seckey := fs.String("s", "", "Secret (private) key produced by -G, and used by -S to sign a message.")
	sigfile := fs.String("x", "", "The signature file to create or verify. The default is message.sig.")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	if *CFLAG {
		verb = CHECK
	}
	if *GFlag {
		if verb != NONE {
			usage()
			return flag.ErrHelp
		}
		verb = GENERATE
	}
	if *SFlag {
		if verb != NONE {
			usage()
			return flag.ErrHelp
		}
		verb = SIGN
	}
	if *VFlag {
		if verb != NONE {
			usage()
			return flag.ErrHelp
		}
		verb = VERIFY
	}
	if *nFlag {
		rounds = 0
	}

	if verb == CHECK {
		if *sigfile == "" {
			fmt.Fprintln(os.Stderr, "must specify sigfile")
			usage()
			return flag.ErrHelp
		}
		if err := check(*pubkey, *sigfile, *qFlag); err != nil {
			return err
		}
		return nil
	}

	if fs.NArg() != 0 {
		usage()
		return flag.ErrHelp
	}

	if *sigfile == "" && *msgfile != "" {
		if *msgfile == "-" {
			fmt.Fprintln(os.Stderr, "must specify sigfile with - message")
			usage()
			return flag.ErrHelp
		}
		*sigfile = fmt.Sprintf("%s.sig", *msgfile)
	}

	switch verb {
	case GENERATE:
		if *pubkey == "" || *seckey == "" {
			fmt.Fprintln(os.Stderr, "must specify pubkey and seckey")
			usage()
			return flag.ErrHelp
		}
		if err := generate(*pubkey, *seckey, rounds, *comment); err != nil {
			return err
		}
	case SIGN:
		if *msgfile == "" || *seckey == "" {
			fmt.Fprintln(os.Stderr, "must specify message and seckey")
			usage()
			return flag.ErrHelp
		}
		if err := sign(*seckey, *msgfile, *sigfile, *eFlag); err != nil {
			return err
		}
	case VERIFY:
		if *msgfile == "" {
			fmt.Fprintln(os.Stderr, "must specify message")
			usage()
			return flag.ErrHelp
		}
		if err := verify(*pubkey, *msgfile, *sigfile, *eFlag, *qFlag); err != nil {
			return err
		}
	default:
		usage()
		return flag.ErrHelp
	}
	return nil
}
