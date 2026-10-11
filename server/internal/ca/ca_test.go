package ca_test

import (
	"context"
	"crypto/rand"
	"strings"
	"testing"

	"privatephone/server/internal/ca"
	"privatephone/server/internal/db"
)

func TestCreateRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	st, err := db.Open(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close(context.Background())

	res, err := ca.Create(context.Background(), st, "admin", "admin")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.Subscriber.Callsign != "admin" || res.Subscriber.Role != "admin" {
		t.Fatalf("bad subscriber: %+v", res.Subscriber)
	}
	if !strings.Contains(res.PrivatePEM, "PRIVATE KEY") || !strings.Contains(res.PublicPEM, "PUBLIC KEY") {
		t.Fatal("must return both PEMs")
	}

	sub, err := st.SubscriberByCallsign(context.Background(), "admin")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if sub.PubKey != res.PublicPEM {
		t.Fatal("vault must hold the issued public key")
	}

	// duplicate callsign rejected
	if _, err := ca.Create(context.Background(), st, "admin", "operator"); err == nil {
		t.Fatal("duplicate callsign must error")
	}
}
