//go:build !darwin && !linux

package adapter

import (
	"errors"
	"os"
)

func lockFile(_ *os.File) error {
	return errors.New("adapter: local durable outbox currently requires macOS/iOS or Linux")
}
