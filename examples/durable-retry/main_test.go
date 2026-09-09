package main

import "testing"

func TestDurableRetryExample(t *testing.T) {
	if err := run(); err != nil {
		t.Fatal(err)
	}
}
