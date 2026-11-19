package main

import (
	"strings"
	"testing"

	"github.com/WillBeebe/nexum/v2/nex"
)

func TestCoordination(t *testing.T) {
	got, err := run(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got.Patch != nex.TaskAccepted || got.Window != nex.TaskAccepted || got.Safety != nex.TaskIncomplete ||
		got.Recommendation != nex.TaskAccepted || !got.StaleClaimRejected || !got.IncompleteBlocked || got.PortableHandoffs != 3 {
		t.Fatalf("unexpected coordination outcomes: %+v", got)
	}
	if !strings.Contains(got.Decision, "Hold Monday 16:00 UTC release") {
		t.Fatalf("unexpected recommendation: %q", got.Decision)
	}
}
