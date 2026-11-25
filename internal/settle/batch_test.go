package settle

import (
	"testing"
	"time"
)

func TestRootEmptyIsStable(t *testing.T) {
	a := Root(nil)
	b := Root(nil)
	if a == "" || a != b {
		t.Fatalf("empty root %q %q", a, b)
	}
}

func TestRootOrderMatters(t *testing.T) {
	h1 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	h2 := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if Root([]string{h1, h2}) == Root([]string{h2, h1}) {
		t.Fatal("expected order-sensitive root")
	}
}

func TestRootOddLeaf(t *testing.T) {
	h := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	got := Root([]string{h})
	if len(got) != 64 {
		t.Fatalf("single leaf root len = %d, want 64 (%q)", len(got), got)
	}
	if got != Root([]string{h}) {
		t.Fatal("single leaf root not deterministic")
	}
	if got == h {
		t.Fatalf("single leaf root must be domain-separated from raw leaf %s", h)
	}
	if got == Root(nil) || got == Root([]string{h, h}) {
		t.Fatalf("single leaf root collided with empty or duplicate leaf list: %s", got)
	}
}

func TestCommit(t *testing.T) {
	now := time.Date(2026, 9, 2, 8, 0, 0, 0, time.UTC)
	b := Commit(1, []string{"aa", "bb"}, []string{"n1"}, []string{"a1"}, []string{"cpu", "cuda"}, TokenNEXForTest(), 2, now)
	if b.Height != 1 || b.Agreements != 1 || b.GPUs != 2 {
		t.Fatalf("%+v", b)
	}
	if b.ReceiptRoot == "" {
		t.Fatal("missing root")
	}
	if b.Token != "NEX" {
		t.Fatalf("token %q", b.Token)
	}
}

func TokenNEXForTest() string { return "NEX" }
