package erofstest

import (
	"os/exec"
	"strings"
	"sync"
	"testing"
)

// MkfsErofsLZ4 returns a Converter that runs mkfs.erofs with `-z lz4` plus
// `-Elegacy-compress` to force the full lcluster layout (the only compressed
// layout the reader currently supports). Pass any additional mkfs.erofs flags
// via extraOpts.
//
// Tests that use this should also call [RequireMkfsLZ4] first to t.Skip when
// the local mkfs.erofs lacks LZ4 support.
func MkfsErofsLZ4(extraOpts ...string) Converter {
	return MkfsErofs(append([]string{"-z", "lz4", "-Elegacy-compress"}, extraOpts...)...)
}


var (
	mkfsLZ4Once   sync.Once
	mkfsLZ4Avail  bool
	mkfsLZ4Reason string
)

// RequireMkfsLZ4 skips t when mkfs.erofs is not on PATH or does not support
// LZ4 compression.
func RequireMkfsLZ4(t testing.TB) {
	t.Helper()
	mkfsLZ4Once.Do(checkMkfsLZ4)
	if !mkfsLZ4Avail {
		t.Skipf("mkfs.erofs lz4 unavailable: %s", mkfsLZ4Reason)
	}
}

func checkMkfsLZ4() {
	if _, err := exec.LookPath("mkfs.erofs"); err != nil {
		mkfsLZ4Reason = "mkfs.erofs not on PATH"
		return
	}
	cmd := exec.Command("mkfs.erofs", "--help")
	out, _ := cmd.CombinedOutput()
	help := strings.ToLower(string(out))
	if !strings.Contains(help, "lz4") {
		mkfsLZ4Reason = "mkfs.erofs --help does not advertise lz4"
		return
	}
	mkfsLZ4Avail = true
}

// MkfsErofsZstd returns a Converter that runs mkfs.erofs with `-z zstd`
// (compact lcluster layout, big_pcluster_1 enabled — the modern default for
// the Zstd algorithm).
func MkfsErofsZstd(extraOpts ...string) Converter {
	return MkfsErofs(append([]string{"-z", "zstd"}, extraOpts...)...)
}

// RequireMkfsZstd skips t when mkfs.erofs lacks Zstd support.
func RequireMkfsZstd(t testing.TB) {
	t.Helper()
	mkfsZstdOnce.Do(checkMkfsZstd)
	if !mkfsZstdAvail {
		t.Skipf("mkfs.erofs zstd unavailable: %s", mkfsZstdReason)
	}
}

var (
	mkfsZstdOnce   sync.Once
	mkfsZstdAvail  bool
	mkfsZstdReason string
)

func checkMkfsZstd() {
	if _, err := exec.LookPath("mkfs.erofs"); err != nil {
		mkfsZstdReason = "mkfs.erofs not on PATH"
		return
	}
	cmd := exec.Command("mkfs.erofs", "--help")
	out, _ := cmd.CombinedOutput()
	if !strings.Contains(strings.ToLower(string(out)), "zstd") {
		mkfsZstdReason = "mkfs.erofs --help does not advertise zstd"
		return
	}
	mkfsZstdAvail = true
}
