package signify

import (
	"os"
	"path/filepath"
)

// getSafePath returns the trusted directory for public keys.
// On Windows, this is %ProgramData%\signify\.
func getSafePath() string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return filepath.Join(programData, "signify") + string(filepath.Separator)
}
