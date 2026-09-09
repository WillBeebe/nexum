//go:build darwin || linux

package nex

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockStoreFile(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX)
}
