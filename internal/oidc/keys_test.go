package oidc

import "testing"

func TestNewKeysSeedDeterministic(t *testing.T) {
	a, err := NewKeys("", "", "my-seed")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewKeys("", "", "my-seed")
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewKeys("", "", "other-seed")
	if err != nil {
		t.Fatal(err)
	}
	if a.PublicKey().N.BitLen() != 2048 {
		t.Fatalf("expected 2048 bit key, got %d", a.PublicKey().N.BitLen())
	}
	if a.KID() != b.KID() || a.PublicKey().N.Cmp(b.PublicKey().N) != 0 {
		t.Fatal("same seed produced different keys")
	}
	if a.KID() == c.KID() {
		t.Fatal("different seeds produced the same key")
	}
}
