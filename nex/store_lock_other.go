//go:build !darwin && !linux

package nex

import (
	"errors"
	"os"
)

func lockStoreFile(_ *os.File) error {
	return errors.New("nex: local durable store currently requires macOS/iOS or Linux")
}
