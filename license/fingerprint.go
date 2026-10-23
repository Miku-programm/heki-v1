package license

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// machineIDPaths is the ordered list of files probed for the Linux machine id,
// matching the binary (dbus id first, then systemd's /etc/machine-id).
var machineIDPaths = []string{
	"/var/lib/dbus/machine-id",
	"/etc/machine-id",
}

// fingerprintSalt is mixed into the raw machine id before hashing.
// Recovered constant: getMachineFingerprint -> protectedID(id, "heki-license-v1").
const fingerprintSalt = "heki-license-v1"

// getMachineFingerprint returns a stable per-machine fingerprint. It reads the
// raw machine id, then protects it by hashing with a fixed salt so the raw id is
// never stored or transmitted in the clear.
func getMachineFingerprint() (string, error) {
	raw, err := readLinuxMachineID()
	if err != nil {
		return "", fmt.Errorf("cannot read machine id: %w", err)
	}
	return protectedID(raw, fingerprintSalt), nil
}

// readLinuxMachineID reads the first non-empty machine id file, falling back to
// "host-"+hostname, and finally erroring with "machine-id not found".
func readLinuxMachineID() (string, error) {
	for _, p := range machineIDPaths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if id := strings.TrimSpace(string(b)); id != "" {
			return id, nil
		}
	}
	if host, err := os.Hostname(); err == nil && host != "" {
		return "host-" + host, nil
	}
	return "", fmt.Errorf("machine-id not found")
}

// protectedID = hex(SHA-256(id || salt)). Recovered from protectedID: two
// SHA-256 writes (id, then salt) followed by Sum and a %x format.
func protectedID(id, salt string) string {
	h := sha256.New()
	h.Write([]byte(id))
	h.Write([]byte(salt))
	return hex.EncodeToString(h.Sum(nil))
}
