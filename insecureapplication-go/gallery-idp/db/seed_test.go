package db

import (
	"testing"
)

func TestSeed_Idempotent(t *testing.T) {
	database := newTestDB(t)

	// First seed run
	if err := database.Seed(); err != nil {
		t.Fatalf("first seed failed: %v", err)
	}

	// Second seed run (default env)
	if err := database.Seed(); err != nil {
		t.Fatalf("second seed failed: %v", err)
	}

	// Third seed run with custom CLIENT_ID
	t.Setenv("CLIENT_ID", "custom-client")
	t.Setenv("CLIENT_SECRET", "custom-secret")

	if err := database.Seed(); err != nil {
		t.Fatalf("seed with custom CLIENT_ID failed: %v", err)
	}

	// Fourth seed run with custom CLIENT_ID (re-running)
	if err := database.Seed(); err != nil {
		t.Fatalf("subsequent seed with custom CLIENT_ID failed: %v", err)
	}

	c, err := database.GetClient("custom-client")
	if err != nil {
		t.Fatalf("get custom client: %v", err)
	}
	if c == nil {
		t.Fatal("expected custom-client to exist")
	}
	if c.ClientSecret != "custom-secret" {
		t.Fatalf("expected custom-secret, got %q", c.ClientSecret)
	}
}
