package network

import (
	"bytes"
	"testing"
)

func TestGameDedupSlidingWindowAndEpochReset(t *testing.T) {
	var d gameDedup
	const ep1 uint32 = 1001
	const ep2 uint32 = 2002

	if !d.accept(ep1, 1) {
		t.Fatal("first packet should be accepted")
	}
	if d.accept(ep1, 1) {
		t.Fatal("duplicate packet should be rejected")
	}
	if !d.accept(ep1, 5) || !d.accept(ep1, 3) || !d.accept(ep1, 2) {
		t.Fatal("out-of-order packets within window should be accepted")
	}
	if d.accept(ep1, 3) {
		t.Fatal("replayed out-of-order packet should be rejected")
	}
	// Simulate client restart: new epoch with seq=1 must immediately succeed!
	if !d.accept(ep2, 1) {
		t.Fatal("new epoch after peer restart must reset sliding window and accept seq=1")
	}
	if d.accept(ep2, 1) {
		t.Fatal("duplicate in new epoch should be rejected")
	}
}

func TestGameDatagramSealOpenAndPortMap(t *testing.T) {
	aead, err := newGameAEAD("my-game-secret")
	if err != nil {
		t.Fatalf("newGameAEAD failed: %v", err)
	}
	payload := []byte("udp-game-frame-xyz")
	raw := sealGameDatagram(aead, gamePktUp, 77, 42, 9, 27015, payload)

	pt, ep, seq, fid, tport, got, ok := openGameDatagram(aead, raw)
	if !ok {
		t.Fatal("openGameDatagram failed on valid packet")
	}
	if pt != gamePktUp || ep != 77 || seq != 42 || fid != 9 || tport != 27015 || !bytes.Equal(got, payload) {
		t.Fatalf("decoded mismatch: pt=%d ep=%d seq=%d fid=%d port=%d payload=%q", pt, ep, seq, fid, tport, string(got))
	}

	// Tampered packet must fail AEAD authentication
	raw[len(raw)-1] ^= 0xFF
	if _, _, _, _, _, _, ok := openGameDatagram(aead, raw); ok {
		t.Fatal("tampered packet must be rejected")
	}

	rules := parseGamePortMap([]string{"3074", "27015=10.0.0.5:27016", "40000-40002"})
	if len(rules) != 5 {
		t.Fatalf("expected 5 expanded rules, got %d", len(rules))
	}
	if rules[1].targetHost != "10.0.0.5" || rules[1].targetPort != 27016 {
		t.Fatalf("unexpected custom target rule: %+v", rules[1])
	}
}
