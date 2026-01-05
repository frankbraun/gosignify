// Package signify implements OpenBSD's signify tool for creating and verifying
// Ed25519 digital signatures. It supports key generation, message signing,
// signature verification, and SHA256/SHA512 checksum validation.
//
// This is a Go reimplementation aiming for full compatibility with the original
// C implementation while adding support for Linux-style checksums.
package signify

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/ebfe/bcrypt_pbkdf"
	"github.com/frankbraun/gosignify/internal/hash"
	"github.com/frankbraun/gosignify/internal/util"
	"golang.org/x/term"
)

const (
	sigbytes         = ed25519.SignatureSize
	secretbytes      = ed25519.PrivateKeySize
	publicbytes      = ed25519.PublicKeySize
	pkalg            = "Ed"
	kdfalg           = "BK"
	keynumlen        = 8
	checksumLen      = 8 // bcrypt_pbkdf checksum prefix length
	commenthdr       = "untrusted comment: "
	commentmaxlen    = 1024
	verifywith       = "verify with "
	defaultKDFRounds = 42 // bcrypt_pbkdf rounds for key derivation
)

type enckey struct {
	Pkalg     [2]byte
	Kdfalg    [2]byte
	Kdfrounds [4]byte
	Salt      [16]byte
	Checksum  [checksumLen]byte
	Keynum    [keynumlen]byte
	Seckey    [secretbytes]byte
}

type pubkey struct {
	Pkalg  [2]byte
	Keynum [keynumlen]byte
	Pubkey [publicbytes]byte
}

type sig struct {
	Pkalg  [2]byte
	Keynum [keynumlen]byte
	Sig    [sigbytes]byte
}

var (
	// argv0 holds the program name for usage messages.
	argv0 string
	// fs is the flag set used for command-line argument parsing.
	fs *flag.FlagSet
	// bsdchecksum matches BSD-style checksum lines: "ALGO (filename) = hash"
	bsdchecksum = regexp.MustCompile(`^(\w+) \((.+)\) = ([0-9a-f]+)$`)
	// linuxchecksum matches Linux-style checksum lines: "hash  filename"
	linuxchecksum = regexp.MustCompile(`^([0-9a-f]+)  (.+)$`)
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage:")
	fmt.Fprintf(os.Stderr, "\t%s -C [-q] -p pubkey -x sigfile [file ...]\n", argv0)
	fmt.Fprintf(os.Stderr, "\t%s -G [-n] [-c comment] -p pubkey -s seckey\n", argv0)
	fmt.Fprintf(os.Stderr, "\t%s -S [-e] [-x sigfile] -s seckey -m message\n", argv0)
	fmt.Fprintf(os.Stderr, "\t%s -V [-eq] [-x sigfile] -p pubkey -m message\n", argv0)
	fs.PrintDefaults()
}

func xopen(fname string, oflags, mode int) (*os.File, error) {
	var (
		fd  *os.File
		err error
	)
	if fname == "-" {
		if oflags&os.O_WRONLY > 0 {
			fdsc, err := util.Dup(os.Stdout.Fd())
			if err != nil {
				return nil, err
			}
			fd = os.NewFile(fdsc, "stdout")
		} else {
			fdsc, err := util.Dup(os.Stdin.Fd())
			if err != nil {
				return nil, err
			}
			fd = os.NewFile(fdsc, "stdin")
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
	if len(lines) < 2 || !strings.HasPrefix(lines[0], commenthdr) {
		return "", nil, nil, fmt.Errorf("invalid comment in %s; must start with '%s'", filename, commenthdr)
	}
	comment := strings.TrimSuffix(lines[0], "\n")
	if len(comment) >= commentmaxlen {
		return "", nil, nil, errors.New("comment too long") // for compatibility
	}
	comment = strings.TrimPrefix(comment, commenthdr)
	if !strings.HasSuffix(lines[1], "\n") {
		return "", nil, nil, fmt.Errorf("missing new line after base64 in %s", filename)
	}
	enc := strings.TrimSuffix(lines[1], "\n")
	buf, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", nil, nil, fmt.Errorf("invalid base64 encoding in %s", filename)
	}
	if len(buf) < 2 || string(buf[:2]) != pkalg {
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
	b64, err := io.ReadAll(fd)
	if err != nil {
		return "", nil, err
	}
	util.MlockBytes(b64)
	defer util.MunlockBytes(b64)
	defer util.BzeroBytes(b64)
	buf, comment, _, err := parseb64file(filename, b64)
	if err != nil {
		return "", nil, err
	}
	return buf, comment, nil
}

func readmsg(filename string) ([]byte, error) {
	fd, err := xopen(filename, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	msg, err := io.ReadAll(fd)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func writeb64file(filename, comment string, data any, msg []byte, oflags, mode int) error {
	fd, err := xopen(filename, os.O_CREATE|oflags|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer fd.Close()
	header := fmt.Sprintf("%s%s\n", commenthdr, comment)
	if len(header) >= commentmaxlen {
		return errors.New("comment too long") // for compatibility
	}
	if _, err := fd.WriteString(header); err != nil {
		return err
	}
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, data); err != nil {
		return err
	}
	length := base64.StdEncoding.EncodedLen(len(buf.Bytes()))
	b64 := make([]byte, length+1)
	util.MlockBytes(b64)
	defer util.MunlockBytes(b64)
	defer util.BzeroBytes(b64)
	base64.StdEncoding.Encode(b64, buf.Bytes())
	b64[length] = '\n'
	if _, err := fd.Write(b64); err != nil {
		return err
	}
	util.BzeroBytes(b64) // wipe early, wipe often
	if len(msg) > 0 {
		if _, err := fd.Write(msg); err != nil {
			return err
		}
	}
	return nil
}

// readPassphrase reads a passphrase from stdin, handling both terminal and pipe input.
// The returned passphrase is memory-locked; caller must call MunlockBytes and BzeroBytes.
func readPassphrase(prompt string, isTerminal bool, reader *bufio.Reader) ([]byte, error) {
	var (
		pass []byte
		err  error
	)
	fmt.Printf("%s", prompt)
	if isTerminal {
		pass, err = term.ReadPassword(0)
		fmt.Println("")
	} else {
		pass, err = reader.ReadBytes('\n')
	}
	if err != nil {
		if err == io.EOF {
			return nil, errors.New("unable to read passphrase")
		}
		return nil, err
	}
	util.MlockBytes(pass)
	if len(pass) == 0 {
		util.MunlockBytes(pass)
		return nil, errors.New("please provide a password")
	}
	return bytes.TrimRight(pass, "\n"), nil
}

// deriveKey derives a key from the passphrase using bcrypt_pbkdf.
func deriveKey(pass, salt []byte, rounds, keyLen int) []byte {
	k := bcrypt_pbkdf.Key(pass, salt, rounds, keyLen)
	util.MlockBytes(k)
	return k
}

func kdf(salt []byte, rounds int, confirm bool, key []byte) error {
	if rounds == 0 {
		// key is already initialized to zero, no need to do it again
		return nil
	}

	isTerminal := term.IsTerminal(0)
	var reader *bufio.Reader
	if !isTerminal {
		reader = bufio.NewReader(os.Stdin)
	}

	// read passphrase from stdin
	pass, err := readPassphrase("passphrase: ", isTerminal, reader)
	if err != nil {
		return err
	}
	defer util.MunlockBytes(pass)
	defer util.BzeroBytes(pass)

	// confirm passphrase, if necessary
	if confirm {
		pass2, err := readPassphrase("confirm passphrase: ", isTerminal, reader)
		if err != nil {
			return err
		}
		defer util.MunlockBytes(pass2)
		defer util.BzeroBytes(pass2)

		if !bytes.Equal(pass, pass2) {
			return errors.New("passwords don't match")
		}
		util.BzeroBytes(pass2) // wipe early, wipe often
		runtime.GC()           // remove potential intermediate slice
	}

	k := deriveKey(pass, salt, rounds, len(key))
	defer util.MunlockBytes(k)
	defer util.BzeroBytes(k)
	copy(key, k)
	runtime.GC() // remove potential intermediate slice

	return nil
}

func generate(pubkeyfile, seckeyfile string, rounds int, comment string) error {
	var (
		pubkey pubkey
		enckey enckey
		xorkey [secretbytes]byte
		keynum [keynumlen]byte
	)
	util.MlockStruct(&enckey)
	defer util.MunlockStruct(&enckey)
	defer util.BzeroStruct(&enckey)
	util.MlockBytes(xorkey[:])
	defer util.MunlockBytes(xorkey[:])
	defer util.BzeroBytes(xorkey[:])

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	copy(pubkey.Pubkey[:], publicKey[:])
	copy(enckey.Seckey[:], privateKey[:])
	if _, err := io.ReadFull(rand.Reader, keynum[:]); err != nil {
		return err
	}

	digest := hash.SHA512(privateKey[:])
	util.MlockBytes(digest)
	defer util.MunlockBytes(digest)
	defer util.BzeroBytes(digest)

	copy(enckey.Pkalg[:], []byte(pkalg))
	copy(enckey.Kdfalg[:], []byte(kdfalg))
	binary.BigEndian.PutUint32(enckey.Kdfrounds[:], uint32(rounds))
	copy(enckey.Keynum[:], keynum[:])
	if _, err := io.ReadFull(rand.Reader, enckey.Salt[:]); err != nil {
		return err
	}
	if err := kdf(enckey.Salt[:], rounds, true, xorkey[:]); err != nil {
		return err
	}
	copy(enckey.Checksum[:], digest[:])
	for i := range enckey.Seckey {
		enckey.Seckey[i] ^= xorkey[i]
	}
	util.BzeroBytes(digest)    // wipe early, wipe often
	util.BzeroBytes(xorkey[:]) // wipe early, wipe often

	commentbuf := fmt.Sprintf("%s secret key", comment)
	if len(commentbuf) >= commentmaxlen {
		return errors.New("comment too long") // for compatibility
	}
	if err := writeb64file(seckeyfile, commentbuf, &enckey, nil, os.O_EXCL, 0600); err != nil {
		return err
	}
	util.BzeroStruct(&enckey) // wipe early, wipe often

	copy(pubkey.Pkalg[:], []byte(pkalg))
	copy(pubkey.Keynum[:], keynum[:])
	commentbuf = fmt.Sprintf("%s public key", comment)
	if len(commentbuf) >= commentmaxlen {
		return errors.New("comment too long") // for compatibility
	}
	return writeb64file(pubkeyfile, commentbuf, &pubkey, nil, os.O_EXCL, 0644)
}

func sign(seckeyfile, msgfile, sigfile string, embedded bool) error {
	var (
		sig        sig
		enckey     enckey
		xorkey     [secretbytes]byte
		sigcomment string
	)
	util.MlockStruct(&enckey)
	defer util.MunlockStruct(&enckey)
	defer util.BzeroStruct(&enckey)
	util.MlockBytes(xorkey[:])
	defer util.MunlockBytes(xorkey[:])
	defer util.BzeroBytes(xorkey[:])

	comment, buf, err := readb64file(seckeyfile)
	if err != nil {
		return err
	}
	if err := binary.Read(bytes.NewReader(buf), binary.BigEndian, &enckey); err != nil {
		return err
	}

	if string(enckey.Kdfalg[:]) != kdfalg {
		return fmt.Errorf("unsupported KDF algorithm: %q", string(enckey.Kdfalg[:]))
	}
	rounds := binary.BigEndian.Uint32(enckey.Kdfrounds[:])

	if err := kdf(enckey.Salt[:], int(rounds), false, xorkey[:]); err != nil {
		return err
	}
	for i := range enckey.Seckey {
		enckey.Seckey[i] ^= xorkey[i]
	}
	util.BzeroBytes(xorkey[:]) // wipe early, wipe often
	digest := hash.SHA512(enckey.Seckey[:])
	util.MlockBytes(digest)
	defer util.MunlockBytes(digest)
	defer util.BzeroBytes(digest)
	if !bytes.Equal(enckey.Checksum[:], digest[:checksumLen]) {
		return errors.New("incorrect passphrase")
	}
	util.BzeroBytes(digest) // wipe early, wipe often

	msg, err := readmsg(msgfile)
	if err != nil {
		return err
	}

	copy(sig.Sig[:], ed25519.Sign(enckey.Seckey[:], msg))
	sig.Keynum = enckey.Keynum
	util.BzeroStruct(&enckey) // wipe early, wipe often

	copy(sig.Pkalg[:], []byte(pkalg))
	if strings.HasSuffix(seckeyfile, ".sec") {
		prefix := strings.TrimSuffix(seckeyfile, ".sec")
		sigcomment = fmt.Sprintf("%s%s.pub", verifywith, prefix)
		if len(sigcomment) >= commentmaxlen {
			return errors.New("comment too long") // for compatibility
		}
	} else {
		sigcomment = fmt.Sprintf("signature from %s", comment)
		if len(sigcomment) >= commentmaxlen {
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
	if !ed25519.Verify(pubkey.Pubkey[:], msg, sig.Sig[:]) {
		return errors.New("signature verification failed")
	}
	if !quiet {
		fmt.Println("Signature Verified")
	}
	return nil
}

func readpubkey(pubkeyfile, sigcomment string) ([]byte, error) {
	safepath := getSafePath()

	if pubkeyfile == "" {
		if _, after, found := strings.Cut(sigcomment, verifywith); found {
			pubkeyfile = after
			// Clean the path and verify it's within the safe directory
			cleanPath := filepath.Clean(pubkeyfile)
			if !strings.HasPrefix(cleanPath, safepath) {
				return nil, fmt.Errorf("untrusted path %s", pubkeyfile)
			}
			pubkeyfile = cleanPath
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
	return buf, nil
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
	if err != nil {
		return err
	}
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
	if err != nil {
		return nil, err
	}
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

type checksum struct {
	file string
	hash string
	algo string
}

func recodehash(hash *string, size int) error {
	if len(*hash) == 2*size {
		// encoding is in hex
		return nil
	}
	// decode base64 encoding
	h, err := base64.StdEncoding.DecodeString(*hash)
	if err != nil {
		return err
	}
	// re-encode in hex
	*hash = hex.EncodeToString(h)
	return nil
}

func verifychecksum(c *checksum, quiet bool) (bool, error) {
	var (
		buf string
		err error
	)
	switch c.algo {
	case "SHA256":
		if err := recodehash(&c.hash, hash.SHA256Size); err != nil {
			return false, err
		}
		buf, err = hash.SHA256File(c.file)
		if err != nil {
			return false, err
		}
	case "SHA512":
		if err := recodehash(&c.hash, hash.SHA512Size); err != nil {
			return false, err
		}
		buf, err = hash.SHA512File(c.file)
		if err != nil {
			return false, err
		}
	default:
		return false, fmt.Errorf("can't handle algorithm %s", c.algo)
	}
	if buf != c.hash {
		return false, nil
	}
	if !quiet {
		fmt.Printf("%s: OK\n", c.file)
	}
	return true, nil
}

func setAlgo(c *checksum) bool {
	switch l := len(c.hash); {
	case l == hash.SHA256Size*2: // hex-encoded length
		c.algo = "SHA256"
	case l == hash.SHA512Size*2: // hex-encoded length
		c.algo = "SHA512"
	default:
		return false
	}
	return true
}

// parseChecksumLine parses a single checksum line in either BSD or Linux format.
// BSD format: ALGO (filename) = hash
// Linux format: hash  filename
func parseChecksumLine(line string) (*checksum, error) {
	var c checksum

	// try to parse BSD-style line
	match := bsdchecksum.FindStringSubmatch(line)
	if match != nil && len(match) == 4 {
		c.algo = match[1]
		c.file = strings.TrimSuffix(match[2], ")")
		c.hash = match[3]
		return &c, nil
	}

	// parsing failed, try to parse Linux-style
	match = linuxchecksum.FindStringSubmatch(line)
	if match == nil || len(match) != 3 {
		return nil, fmt.Errorf("unable to parse checksum line %s", line)
	}
	c.hash = match[1]
	c.file = match[2]
	if !setAlgo(&c) {
		return nil, fmt.Errorf("unable to parse checksum line %s", line)
	}
	return &c, nil
}

// verifyFileChecksum verifies a single file's checksum and updates tracking state.
// Returns true if verification passed, false if failed or skipped.
func verifyFileChecksum(c *checksum, checkFiles map[string]bool, filterByArgs bool, quiet bool) (bool, error) {
	if filterByArgs && !checkFiles[c.file] {
		return false, nil // skip files not in args
	}

	chk, err := verifychecksum(c, quiet)
	if err != nil {
		return false, err
	}

	if filterByArgs && chk {
		delete(checkFiles, c.file)
	} else if !filterByArgs && !chk {
		checkFiles[c.file] = true
	}
	return chk, nil
}

func verifychecksums(msg []byte, args []string, quiet bool) error {
	checkFiles := make(map[string]bool)
	for _, arg := range args {
		checkFiles[arg] = true
	}
	filterByArgs := len(args) > 0

	scanner := bufio.NewScanner(bytes.NewBuffer(msg))
	for scanner.Scan() {
		c, err := parseChecksumLine(scanner.Text())
		if err != nil {
			return err
		}
		if _, err := verifyFileChecksum(c, checkFiles, filterByArgs, quiet); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	// report any files that failed verification
	var hasFailed bool
	for k := range checkFiles {
		fmt.Fprintf(os.Stderr, "%s: FAIL\n", k)
		hasFailed = true
	}
	if hasFailed {
		return flag.ErrHelp
	}
	return nil
}

func check(pubkeyfile, sigfile string, args []string, quiet bool) error {
	msg, err := verifyembedded(pubkeyfile, sigfile, quiet)
	if err != nil {
		return err
	}
	return verifychecksums(msg, args, quiet)
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
	rounds := defaultKDFRounds

	if len(args) == 0 {
		return errors.New("at least one argument is mandatory")
	}

	argv0 = args[0]
	fs = flag.NewFlagSet(argv0, flag.ContinueOnError)
	fs.Usage = usage
	CFlag := fs.Bool("C", false, "Verify a signed checksum list, and then verify the checksum for each file. If no files are specified, all of them are checked. sigfile should be the signed output of sha256(1).")
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

	if *CFlag {
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
		return check(*pubkey, *sigfile, fs.Args(), *qFlag)
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
