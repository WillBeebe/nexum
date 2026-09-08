package message

import (
	"testing"
	"time"
)

func TestPublicBaselineRejectsUnsupportedSuite(t *testing.T) {
	a, b := identity(t), identity(t)
	now := time.Now().UTC()
	o, _ := offer(t, a, b, now)
	for _, suite := range []string{RekeySuite, "unregistered-suite"} {
		altered := o
		altered.Terms.KeySuite = suite
		altered.Signature = sign(a, "offer", altered.unsigned())
		if altered.Verify() == nil {
			t.Fatal("unsupported suite accepted")
		}
		if _, err := Decide(b, altered, "agree", now); err == nil {
			t.Fatal("unsupported suite accepted by recipient")
		}
	}
}
