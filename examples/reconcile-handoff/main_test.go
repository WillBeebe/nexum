package main

import "testing"

func TestReconcileHandoffExample(t *testing.T) {
	if err := run(); err != nil {
		t.Fatal(err)
	}
}
