package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestReconcileHandoffExample(t *testing.T) {
	var buf bytes.Buffer
	if err := runTo(&buf); err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("decode output: %v (%s)", err, buf.String())
	}
	if out["example"] != "reconcile-handoff" {
		t.Fatalf("unexpected example: %v", out["example"])
	}
	if out["durable_coordinator"] != true {
		t.Fatalf("expected durable_coordinator=true, got %v", out["durable_coordinator"])
	}
	if out["old_owner_rejected"] != true || out["new_owner_active"] != true {
		t.Fatalf("unexpected handoff flags: %v", out)
	}
	if out["fence_generation"] != float64(2) || out["admission_generation"] != float64(2) {
		t.Fatalf("expected generation 2 handoff and resumed admission, got %v", out)
	}
}
