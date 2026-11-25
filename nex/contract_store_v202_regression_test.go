// Regression tests for Nexum v2.0.2 Contract & Store fixes:
//   - BUG-20: nex.New normalizes now/deadline to UTC before Terms hashing, preventing
//             cross-timezone Contract.ID divergence and sub-minute offset Store corruption.
//   - BUG-21: nex.New rejects invalid UTF-8 and NUL bytes in kind before hashing.
//   - BUG-23: nex.New rejects out-of-RFC3339-range time.Time cleanly without panicking.
//   - BUG-24: nex.New rejects buyer and seller sharing identical Ed25519 Signing keys
//             with nexum.ErrSameParty (even with distinct Encryption keys).
//   - R-1:    Contract.rebuildConsent checks r.Actor == c.agreement.Seller so buyer-authored
//             "signed-consent:" settle evidence receipts never append duplicate consent events.

package nex

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/WillBeebe/nexum/v2/internal/nexum"
)

func v202ContractParties(t *testing.T) (Identity, Identity, Public, Public) {
	t.Helper()
	buyer, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	seller, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bp, err := buyer.Public()
	if err != nil {
		t.Fatal(err)
	}
	sp, err := seller.Public()
	if err != nil {
		t.Fatal(err)
	}
	return buyer, seller, bp, sp
}

// BUG-20: nex.New normalizes now/deadline to UTC so sub-minute timezone offsets persist
// and reload cleanly in Store, and identical UTC instants in different timezones yield
// the exact same Contract.ID.
func TestV202_ContractTimezoneNormalizationAndSubMinuteOffset(t *testing.T) {
	_, _, bp, sp := v202ContractParties(t)

	t.Run("subminute_offset_persists_and_reloads", func(t *testing.T) {
		loc := time.FixedZone("LMT", 30)
		now := time.Date(2026, 9, 9, 12, 0, 0, 0, loc)
		deadline := now.Add(time.Hour)

		c, err := New("work.bounty", bp, sp, 10, "spec", now, deadline)
		if err != nil {
			t.Fatal(err)
		}
		if c.definition.Created.Location() != time.UTC || c.definition.Deadline.Location() != time.UTC {
			t.Fatalf("Terms timestamps not normalized to UTC: created=%v deadline=%v", c.definition.Created.Location(), c.definition.Deadline.Location())
		}
		store, err := OpenStore(filepath.Join(t.TempDir(), "s"), bytes.Repeat([]byte{22}, 32))
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Create(c); err != nil {
			t.Fatal(err)
		}
		view, viewErr := store.View(c.ID())
		if viewErr != nil {
			t.Fatalf("Store.View failed for sub-minute timezone contract: %v", viewErr)
		}
		if !view.Terms.Created.Equal(now) || !view.Terms.Deadline.Equal(deadline) {
			t.Fatalf("reloaded timestamps drifted: got (%v, %v), want (%v, %v)",
				view.Terms.Created, view.Terms.Deadline, now.UTC(), deadline.UTC())
		}
	})

	t.Run("same_instant_different_timezone_same_id", func(t *testing.T) {
		utcNow := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
		edtNow := utcNow.In(time.FixedZone("EDT", -4*3600))
		lmtNow := utcNow.In(time.FixedZone("LMT", 30))

		cUTC, err := New("work.bounty", bp, sp, 10, "spec", utcNow, utcNow.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		cEDT, err := New("work.bounty", bp, sp, 10, "spec", edtNow, edtNow.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		cLMT, err := New("work.bounty", bp, sp, 10, "spec", lmtNow, lmtNow.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if cUTC.ID() != cEDT.ID() || cUTC.ID() != cLMT.ID() {
			t.Fatalf("identical UTC instants produced different Contract.IDs: UTC=%s EDT=%s LMT=%s",
				cUTC.ID(), cEDT.ID(), cLMT.ID())
		}
	})
}

// BUG-21: nex.New rejects invalid UTF-8 and NUL bytes in kind cleanly.
func TestV202_ContractNewRejectsInvalidUTF8AndNULKind(t *testing.T) {
	_, _, bp, sp := v202ContractParties(t)
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	deadline := now.Add(time.Hour)

	for _, badKind := range []string{"\xff", "\xfe", "work\xffbounty", "work\x00bounty", "\x00", ""} {
		if _, err := New(badKind, bp, sp, 10, "spec", now, deadline); err == nil {
			t.Fatalf("nex.New accepted invalid kind %q", badKind)
		}
	}
}

// BUG-23: nex.New returns an error cleanly instead of panicking on out-of-RFC3339-range timestamps.
func TestV202_ContractNewRejectsOutOfRangeTimeWithoutPanic(t *testing.T) {
	_, _, bp, sp := v202ContractParties(t)

	cases := []struct {
		name          string
		now, deadline time.Time
	}{
		{
			name:     "year_10000_now_and_deadline",
			now:      time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
			deadline: time.Date(10000, 1, 1, 1, 0, 0, 0, time.UTC),
		},
		{
			name:     "year_10000_deadline_only",
			now:      time.Date(9999, 12, 31, 23, 30, 0, 0, time.UTC),
			deadline: time.Date(10000, 1, 1, 0, 30, 0, 0, time.UTC),
		},
		{
			name:     "negative_year_now",
			now:      time.Date(-1, 12, 31, 23, 0, 0, 0, time.UTC),
			deadline: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name:     "utc_normalization_pushes_year_to_10000",
			now:      time.Date(9999, 12, 31, 23, 30, 0, 0, time.FixedZone("W", -2*3600)),
			deadline: time.Date(9999, 12, 31, 23, 45, 0, 0, time.FixedZone("W", -2*3600)),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("nex.New panicked on %s: %v", tc.name, r)
				}
			}()
			if _, err := New("work.bounty", bp, sp, 10, "spec", tc.now, tc.deadline); err == nil {
				t.Fatalf("expected error for out-of-range time case %s", tc.name)
			}
		})
	}
}

// BUG-24: nex.New rejects two Public identities sharing identical Ed25519 Signing keys
// (even with distinct X25519 Encryption keys) with nexum.ErrSameParty.
func TestV202_ContractNewRejectsSharedSigningKey(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	id1, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	id2, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	id2.Signing = append([]byte(nil), id1.Signing...)
	p1, err := id1.Public()
	if err != nil {
		t.Fatal(err)
	}
	p2, err := id2.Public()
	if err != nil {
		t.Fatal(err)
	}
	if p1.ID() == p2.ID() {
		t.Fatal("test setup expected distinct Public IDs via distinct encryption keys")
	}

	if _, err := New("work.bounty", p1, p2, 10, "spec", now, now.Add(time.Hour)); !errors.Is(err, nexum.ErrSameParty) {
		t.Fatalf("shared signing key returned %v, want nexum.ErrSameParty", err)
	}
}

// R-1 (latent hardening): Contract.rebuildConsent must check r.Actor == c.agreement.Seller
// so a buyer-authored "signed-consent:" settle evidence receipt never appends a duplicate
// consent event to c.consent.
func TestV202_ContractRebuildConsentRequiresSellerActor(t *testing.T) {
	buyer, seller, bp, sp := v202ContractParties(t)
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	c, err := New("work.bounty", bp, sp, 10, "spec", now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	store, err := OpenStore(filepath.Join(t.TempDir(), "s"), bytes.Repeat([]byte{24}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Create(c); err != nil {
		t.Fatal(err)
	}

	applyStore := func(opID, action, evidence string, signer Identity) {
		t.Helper()
		op, err := store.Prepare(c.ID(), opID, action, evidence)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Apply(c.ID(), op, Sign(signer, "operation", op), now); err != nil {
			t.Fatalf("%s: %v", action, err)
		}
	}
	applyStore("op-lock", "lock", "", buyer)
	applyStore("op-agree", "agree", "", seller)
	// Buyer settles with evidence starting with "signed-consent:".
	applyStore("op-settle", "settle", "signed-consent:spoofed-by-buyer", buyer)

	_, restored, err := store.read(c.ID())
	if err != nil {
		t.Fatalf("store.read failed: %v", err)
	}
	history := restored.ConsentHistory()
	if len(history) != 1 {
		t.Fatalf("rebuildConsent appended non-seller evidence receipt: got %d consent events (%+v), want 1", len(history), history)
	}
	// Find seller's "agree" evidence receipt hash and verify history[0] points solely to it.
	var sellerAgreeHead string
	for _, r := range restored.agreement.Receipts {
		if r.Action == "evidence" && r.Actor == restored.agreement.Seller {
			sellerAgreeHead = r.Hash
		}
	}
	if sellerAgreeHead == "" || history[0].Action != "agree" || history[0].Head != sellerAgreeHead {
		t.Fatalf("unexpected consent event %+v, want agree at seller receipt %s", history[0], sellerAgreeHead)
	}

	// Also verify in-memory Execute + direct rebuildConsent produces identical 1-element history.
	if err := c.Execute(buyer, "lock", "", now); err != nil {
		t.Fatal(err)
	}
	if err := c.Execute(seller, "agree", "", now); err != nil {
		t.Fatal(err)
	}
	if err := c.Execute(buyer, "settle", "signed-consent:spoofed-by-buyer", now); err != nil {
		t.Fatal(err)
	}
	c.rebuildConsent()
	if got := c.ConsentHistory(); len(got) != 1 || got[0].Action != "agree" {
		t.Fatalf("direct rebuildConsent produced %+v, want single seller agree event", got)
	}
}
