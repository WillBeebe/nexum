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
	if got == "" {
		t.Fatal("empty")
	}
	// one leaf: the root is that leaf's bytes, hex-encoded (no pair)
	if got != h {
		t.Fatalf("single leaf want %s got %s", h, got)
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
