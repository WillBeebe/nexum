//go:build darwin || linux

package nex

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockStoreFile(f *os.File) error {
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX)
		if err != unix.EINTR {
			return err
		}
	}
}
