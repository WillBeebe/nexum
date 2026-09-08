package settle

import (
	"errors"
	"testing"
)

func TestEncryptedSettlementSumsOnCiphertext(t *testing.T) {
	l, err := NewEncryptedLedger(1024)
	if err != nil {
		t.Fatalf("ledger: %v", err)
	}
	// Three agents seal partial locks. The kernel never sees these ints.
	partials := []int64{300, 450, 250}
	sealed := make([][]byte, 0, len(partials))
	for _, a := range partials {
		c, err := l.SealLock(a)
		if err != nil {
			t.Fatalf("seal %d: %v", a, err)
		}
		sealed = append(sealed, c)
	}
	sum, err := l.Aggregate(sealed)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	got, err := l.Release(sum, 1000)
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if got != 1000 {
		t.Fatalf("got %d, want 1000", got)
	}
}

func TestReleaseRejectsWrongCommittedAmount(t *testing.T) {
	l, _ := NewEncryptedLedger(1024)
	sealed, err := l.SealLock(700)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	sum, err := l.Aggregate([][]byte{sealed})
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if _, err := l.Release(sum, 999); !errors.Is(err, ErrSumMismatch) {
		t.Fatalf("want ErrSumMismatch, got %v", err)
	}
}

func TestAggregateFailsClosedOnEmpty(t *testing.T) {
	l, _ := NewEncryptedLedger(1024)
	if _, err := l.Aggregate(nil); !errors.Is(err, ErrNoLocks) {
		t.Fatalf("want ErrNoLocks, got %v", err)
	}
}

func TestSealLockRejectsNonPositive(t *testing.T) {
	l, _ := NewEncryptedLedger(1024)
	if _, err := l.SealLock(0); !errors.Is(err, ErrBadLock) {
		t.Fatalf("zero lock must refuse with ErrBadLock, got %v", err)
	}
	if _, err := l.SealLock(-5); !errors.Is(err, ErrBadLock) {
		t.Fatalf("negative lock must refuse with ErrBadLock, got %v", err)
	}
}

func TestReleaseRejectsTamperedCiphertext(t *testing.T) {
	l, _ := NewEncryptedLedger(1024)
	c, err := l.SealLock(500)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	c[0] ^= 0xff // flip one byte: malformed on purpose
	if _, err := l.Release(c, 500); err == nil {
		t.Fatal("tampered aggregate must not settle")
	}
}

// Equality proof: the sealed escrow branch is a zero-knowledge equality proof.
// The aggregate of sealed locks must prove it encrypts the committed
// amount — public key only, no Decrypt anywhere on the path.
func TestProveEqualBranchesWithoutDecrypt(t *testing.T) {
	l, err := NewEncryptedLedger(2048)
	if err != nil {
		t.Fatal(err)
	}
	locks := make([][]byte, 2)
	for i, amt := range []int64{200_000, 150_000} {
		ct, err := l.SealLock(amt)
		if err != nil {
			t.Fatal(err)
		}
		locks[i] = ct
	}
	sum, err := l.Aggregate(locks)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := l.ProveEqual(sum, 350_000)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := l.VerifyEqual(sum, 350_000, proof)
	if err != nil || !ok {
		t.Fatalf("honest aggregate proof rejected: ok=%v err=%v", ok, err)
	}
	// A false committed amount must not branch.
	if ok, _ := l.VerifyEqual(sum, 349_999, proof); ok {
		t.Fatal("proof accepted a false committed amount")
	}
	// A forged proof must not verify.
	if ok, _ := l.VerifyEqual(sum, 350_000, []byte("garbage")); ok {
		t.Fatal("garbage proof accepted")
	}
}
