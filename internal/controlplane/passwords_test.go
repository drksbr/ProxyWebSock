package controlplane

import "testing"

func TestPasswordHashAndVerify(t *testing.T) {
	hash, err := HashPassword("super-secret")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if !VerifyPassword(hash, "super-secret") {
		t.Fatal("expected password verification to succeed")
	}
	if VerifyPassword(hash, "wrong-secret") {
		t.Fatal("expected password verification to fail")
	}
}
