# gosignify

[![Build Status](https://travis-ci.org/frankbraun/gosignify.png)](https://travis-ci.org/frankbraun/gosignify)

gosignify is a Go reimplementation of OpenBSD's signify
([manpage](http://www.openbsd.org/cgi-bin/man.cgi/OpenBSD-current/man1/signify.1), [blog post](http://www.tedunangst.com/flak/post/signify), [CVS](http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/signify/)).
It strives to be fully compatible with the original C implementation.

## Installation

	$ go get github.com/frankbraun/gosignify


## TODO

- implement option `-C`
- more tests (coverage and comparison with original implementation)


## Manpage
```
SYNOPSIS
     gosignify -C [-q] -p pubkey -x sigfile [file ...]
     gosignify -G [-n] [-c comment] -p pubkey -s seckey
     gosignify -I [-p pubkey] [-s seckey] [-x sigfile]
     gosignify -S [-e] [-x sigfile] -s seckey -m message
     gosignify -V [-eq] [-x sigfile] -p pubkey -m message

DESCRIPTION
     The gosignify utility creates and verifies cryptographic signatures.  A
     signature verifies the integrity of a message.  The mode of operation is
     selected with the following options:

     -C          Verify a signed checksum list, and then verify the checksum
                 for each file.  If no files are specified, all of them are
                 checked.  sigfile should be the signed output of sha256(1).

     -G          Generate a new key pair.

     -I          Inspect the specified keys or signature and print their fin-
                 gerprint.

     -S          Sign the specified message file and create a signature.

     -V          Verify the message and signature match.

     The other options are as follows:

     -c comment    Specify the comment to be added during key generation.

     -e            When signing, embed the message after the signature.  When
                   verifying, extract the message from the signature.  (This
                   requires that the signature was created using -e and cre-
                   ates a new message file as output.)

     -m message    When signing, the file containing the message to sign.
                   When verifying, the file containing the message to verify.
                   When verifying with -e, the file to create.

     -n            Do not ask for a passphrase during key generation.  Other-
                   wise, gosignify will prompt the user for a passphrase to pro-
                   tect the secret key.

     -p pubkey     Public key produced by -G, and used by -V to check a signa-
                   ture.

     -q            Quiet mode.  Suppress informational output.

     -s seckey     Secret (private) key produced by -G, and used by -S to sign
                   a message.

     -x sigfile    The signature file to create or verify.  The default is
                   message.sig.

     The key and signature files created by gosignify have the same format.  The
     first line of the file is a free form text comment that may be edited, so
     long as it does not exceed a single line.  The second line of the file is
     the actual key or signature base64 encoded.

EXIT STATUS
     The gosignify utility exits 0 on success, and >0 if an error occurs.  It
     may fail because of one of the following reasons:

     o   Some necessary files do not exist.
     o   Entered passphrase is incorrect.
     o   The message file was corrupted and its signature does not match.
     o   The message file is too large.

EXAMPLES
     Create a new key pair:
           $ gosignify -G -p newkey.pub -s newkey.sec

     Sign a file, specifying a signature name:
           $ gosignify -S -s key.sec -m message.txt -x msg.sig

     Verify a signature, using the default signature name:
           $ gosignify -V -p key.pub -m generalsorders.txt

     Verify a release directory containing SHA256.sig and a full set of
     release files:
           $ gosignify -C -p /etc/signify/openbsd-55-base.pub -x SHA256.sig

     Verify a bsd.rd before an upgrade:
           $ gosignify -C -p /etc/signify/openbsd-55-base.pub -x SHA256.sig bsd.rd

SEE ALSO
     fw_update(1), pkg_add(1), sha256(1)

HISTORY
     The signify command first appeared in OpenBSD 5.5.
```
