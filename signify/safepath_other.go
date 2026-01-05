//go:build !windows

package signify

// getSafePath returns the trusted directory for public keys.
// On Unix-like systems, this is /etc/signify/.
func getSafePath() string {
	return "/etc/signify/"
}
