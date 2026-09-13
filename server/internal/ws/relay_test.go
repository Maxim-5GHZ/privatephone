package ws

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestParseRecipients(t *testing.T) {
	if got := parseRecipients(""); got != nil {
		t.Fatalf("empty recipient must mean broadcast, got %v", got)
	}
	if got := parseRecipients("bob"); !reflect.DeepEqual(got, []string{"bob"}) {
		t.Fatalf("single recipient, got %v", got)
	}
	if got := parseRecipients(`["alice","bob"]`); !reflect.DeepEqual(got, []string{"alice", "bob"}) {
		t.Fatalf("array recipient, got %v", got)
	}
	if got := parseRecipients("[broken"); !reflect.DeepEqual(got, []string{"[broken"}) {
		t.Fatalf("malformed array must fall back to a literal callsign, got %v", got)
	}
}

func TestRelayRecipients(t *testing.T) {
	if got := relayRecipients(json.RawMessage(`"bob"`)); !reflect.DeepEqual(got, []string{"bob"}) {
		t.Fatalf("single recipient, got %v", got)
	}
	if got := relayRecipients(json.RawMessage(`["a","b"]`)); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("array recipient, got %v", got)
	}
	if got := relayRecipients(json.RawMessage(`""`)); got != nil {
		t.Fatalf("empty recipient must be dropped, got %v", got)
	}
	if got := relayRecipients(json.RawMessage(``)); len(got) != 0 {
		t.Fatalf("absent recipient must be dropped, got %v", got)
	}
	if got := relayRecipients(json.RawMessage(`42`)); got != nil {
		t.Fatalf("non-string recipient must be dropped, got %v", got)
	}
}

func TestEncCargo(t *testing.T) {
	if _, ok := encCargo(json.RawMessage(`{"lat":1}`)); ok {
		t.Fatal("packet without enc must not report E2EE cargo")
	}
	if _, ok := encCargo(json.RawMessage(`{"enc":""}`)); ok {
		t.Fatal("empty enc must not report E2EE cargo")
	}
	if _, ok := encCargo(json.RawMessage(`not json`)); ok {
		t.Fatal("malformed payload must not report E2EE cargo")
	}
	got, ok := encCargo(json.RawMessage(`{"lat":1,"enc":{"v":2,"c":"abc"}}`))
	if !ok {
		t.Fatal("packet with enc must report E2EE cargo")
	}
	var want map[string]any
	if err := json.Unmarshal([]byte(got), &want); err != nil {
		t.Fatalf("cargo must be valid envelope JSON: %v", err)
	}
	if want["v"] != float64(2) {
		t.Fatalf("cargo envelope must round-trip, got %v", got)
	}
}
