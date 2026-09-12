package api_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/coder/websocket"
)

type pttFrame struct {
	Kind   string          `json:"kind"`
	Sender string          `json:"sender"`
	Data   json.RawMessage `json:"data"`
}

func TestPTTRelayToGroup(t *testing.T) {
	ctx := setup(t)
	alice := register(t, ctx, "alice", "operator")
	bob := register(t, ctx, "bob", "operator")
	carol := register(t, ctx, "carol", "operator")

	cA := wsDial(t, ctx)
	defer cA.Close(websocket.StatusNormalClosure, "")
	wsHello(t, ctx, cA, alice, "alice")

	cB := wsDial(t, ctx)
	defer cB.Close(websocket.StatusNormalClosure, "")
	wsHello(t, ctx, cB, bob, "bob")

	cC := wsDial(t, ctx)
	defer cC.Close(websocket.StatusNormalClosure, "")
	wsHello(t, ctx, cC, carol, "carol")

	// alice opens a PTT session addressed to bob and carol (full-mesh of 3)
	start := signAs(t, "alice", alice, "ptt_start", map[string]any{"n": "ptn1", "to": []string{"bob", "carol"}})
	if err := cA.Write(context.Background(), websocket.MessageText, frameFrom(start)); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*websocket.Conn{cB, cC} {
		msg := readUntilKind(t, c, "ptt_start")
		var f pttFrame
		if err := json.Unmarshal(msg, &f); err != nil {
			t.Fatal(err)
		}
		if f.Sender != "alice" {
			t.Fatalf("ptt_start sender: %s", f.Sender)
		}
		var d struct {
			N  string   `json:"n"`
			To []string `json:"to"`
		}
		if err := json.Unmarshal(f.Data, &d); err != nil {
			t.Fatal(err)
		}
		if d.N != "ptn1" || len(d.To) != 2 {
			t.Fatalf("ptt_start payload: %s", f.Data)
		}
	}

	// single-addressed offer must reach only bob (carol's socket stays quiet:
	// the relay uses the same per-recipient deliver path as call signaling,
	// which TestSignalingRelayOnlyToRecipient proves stays isolated)
	offer := signAs(t, "alice", alice, "ptt_offer", map[string]any{"n": "ptn1", "to": "bob", "sdp": map[string]string{"type": "offer", "sdp": "SDP_B"}})
	if err := cA.Write(context.Background(), websocket.MessageText, frameFrom(offer)); err != nil {
		t.Fatal(err)
	}
	msg := readUntilKind(t, cB, "ptt_offer")
	var f pttFrame
	if err := json.Unmarshal(msg, &f); err != nil {
		t.Fatal(err)
	}
	if f.Sender != "alice" || f.Kind != "ptt_offer" {
		t.Fatalf("bob must get the offer, got %s", msg)
	}

	// bob answers only alice
	ans := signAs(t, "bob", bob, "ptt_answer", map[string]any{"n": "ptn1", "to": "alice", "sdp": map[string]string{"type": "answer", "sdp": "SDP_BA"}})
	if err := cB.Write(context.Background(), websocket.MessageText, frameFrom(ans)); err != nil {
		t.Fatal(err)
	}
	msg = readUntilKind(t, cA, "ptt_answer")
	if err := json.Unmarshal(msg, &f); err != nil {
		t.Fatal(err)
	}
	if f.Sender != "bob" {
		t.Fatalf("alice must get bob's answer, got %s", msg)
	}

	// carol keys the mic → talk status goes to the whole group (including bob)
	talk := signAs(t, "carol", carol, "ptt_talking", map[string]any{"n": "ptn1", "to": []string{"alice", "bob"}, "talks": "carol"})
	if err := cC.Write(context.Background(), websocket.MessageText, frameFrom(talk)); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*websocket.Conn{cA, cB} {
		ta := readUntilKind(t, c, "ptt_talking")
		var pf pttFrame
		if err := json.Unmarshal(ta, &pf); err != nil {
			t.Fatal(err)
		}
		var d struct {
			Talks string `json:"talks"`
		}
		if err := json.Unmarshal(pf.Data, &d); err != nil {
			t.Fatal(err)
		}
		if pf.Sender != "carol" || d.Talks != "carol" {
			t.Fatalf("talking frame: %s", ta)
		}
	}

	// alice ends the session to the group
	end := signAs(t, "alice", alice, "ptt_end", map[string]any{"n": "ptn1", "to": []string{"bob", "carol"}})
	if err := cA.Write(context.Background(), websocket.MessageText, frameFrom(end)); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*websocket.Conn{cB, cC} {
		e := readUntilKind(t, c, "ptt_end")
		var pf pttFrame
		if err := json.Unmarshal(e, &pf); err != nil {
			t.Fatal(err)
		}
		if pf.Sender != "alice" {
			t.Fatalf("ptt_end sender: %s", pf.Sender)
		}
	}
}

// PTT frames are not persisted into the tamper-evident journal (ephemeral).
func TestPTTNotJournaled(t *testing.T) {
	ctx := setup(t)
	bob := register(t, ctx, "bob", "operator")

	cA := wsDial(t, ctx)
	defer cA.Close(websocket.StatusNormalClosure, "")
	wsHello(t, ctx, cA, string(ctx.priv), "admin")

	cB := wsDial(t, ctx)
	defer cB.Close(websocket.StatusNormalClosure, "")
	wsHello(t, ctx, cB, bob, "bob")

	start := signAs(t, "admin", string(ctx.priv), "ptt_start", map[string]any{"n": "ptnj", "to": []string{"bob"}})
	if err := cA.Write(context.Background(), websocket.MessageText, frameFrom(start)); err != nil {
		t.Fatal(err)
	}
	// bob's receipt proves the frame was processed by the hub
	_ = readUntilKind(t, cB, "ptt_start")

	entries, err := ctx.st.ListJournal(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Kind == "ptt_start" {
			t.Fatalf("PTT frame must not be journaled, found kind=%s id=%s", e.Kind, e.ID)
		}
	}
}
