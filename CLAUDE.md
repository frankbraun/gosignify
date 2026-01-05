# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

gosignify is a Go reimplementation of OpenBSD's `signify` tool - a cryptographic signature utility for creating and verifying Ed25519 digital signatures. It aims for full compatibility with the original C implementation while adding Linux-style checksum support.

## Build Commands

```bash
# Build the binary
make all

# Install to /usr/local/bin
make install

# Install to custom location
make install prefix=/custom/path

# Update vendored dependencies
make update-vendor

# Direct Go build (uses vendor directory)
go build -mod vendor -v .
```

## Testing

```bash
# Run all tests
go test -mod vendor -v ./...

# Run with coverage
go test -mod vendor -cover ./...
```

Test data is in `signify/testdata/` - do not modify these binary files as they're used for regression testing against reference signatures.

## Linting

```bash
# Run golangci-lint (used in CI)
golangci-lint run ./...

# Run go vet (also part of CI)
go vet ./...
```

## Architecture

### Package Structure

- **`gosignify.go`** - Entry point, delegates to `signify.Main()`
- **`signify/`** - Core implementation:
  - `signify.go` (~830 lines): key generation, signing, verification, checksum validation
  - `safepath_other.go` / `safepath_windows.go`: platform-specific trusted key directory paths
- **`internal/hash/`** - SHA256/SHA512 file hashing utilities
- **`internal/util/`** - Security utilities with platform-specific implementations:
  - Memory zeroing (`bzero.go`)
  - Memory locking (`mlock_*.go` for Unix/Windows)
  - File descriptor duplication (`dup_*.go`)

### Operation Modes

| Flag | Mode | Purpose |
|------|------|---------|
| `-G` | GENERATE | Create Ed25519 key pair |
| `-S` | SIGN | Sign a message file |
| `-V` | VERIFY | Verify message signature |
| `-C` | CHECK | Verify SHA256/SHA512 checksums |
| `-I` | INSPECT | Print key/signature fingerprints |

### Key Data Structures (signify/signify.go)

- `sig` - Ed25519 signature (algorithm marker + key number + 64-byte signature)
- `pubkey` - Public key (algorithm marker + key number + 32-byte key)
- `enckey` - Encrypted secret key (includes bcrypt_pbkdf parameters, salt, checksum)

### Key Helper Functions (signify/signify.go)

- `readPassphrase()` - Reads passphrase from terminal or pipe with memory locking
- `deriveKey()` - Derives encryption key using bcrypt_pbkdf
- `parseChecksumLine()` - Parses BSD-style or Linux-style checksum lines
- `verifyFileChecksum()` - Verifies a single file's checksum

### Security Patterns

- Secret keys are encrypted with bcrypt_pbkdf (42 rounds default)
- Sensitive data is memory-locked (`Mlock`) and zeroed after use (`Bzero`)
- File permissions: 0600 for secret keys, 0644 for public keys

### File Format

```
untrusted comment: <description>
<base64-encoded-binary-data>
[optional embedded message for -e flag]
```

### Checksum Formats Supported

- BSD-style: `SHA256 (filename) = <hex-hash>`
- Linux-style: `<hex-hash>  filename`
