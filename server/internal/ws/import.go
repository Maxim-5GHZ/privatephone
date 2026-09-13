package ws

import (
	"context"
	"encoding/json"
	"errors"
	"log"

	"privatephone/server/internal/db"
	"privatephone/server/internal/protocol"
)

// journal stores the signed original packet for store-and-forward replay. The
// id is deterministic (sender|kind|nonce|ts) so re-imported bags deduplicate.
func (h *Hub) journal(ctx context.Context, f protocol.Frame, recipient string) {
	id := db.PacketID(f.Sender, f.Kind, f.Nonce, f.TS)
	if err := h.st.AddPacket(ctx, id, f.Sender, f.Kind, string(f.Data), f.Signature, f.Nonce, recipient, f.TS); err != nil &&
		!errors.Is(err, db.ErrDuplicate) {
		log.Printf("journal packet: %v", err)
	}
}

// Journal persists an already-verified packet into the tamper-evident journal
// (used by REST handlers, e.g. admin CRL commands).
func (h *Hub) Journal(ctx context.Context, f protocol.Frame, recipient string) {
	h.journal(ctx, f, recipient)
}

// ImportReport summarizes a journal bag import (sneaker-net).
type ImportReport struct {
	AddedJournal int    `json:"added_journal"`
	SkippedDup   int    `json:"skipped_duplicates"`
	SkippedCtx   int    `json:"skipped_context"`
	Rejected     bool   `json:"rejected"`
	RejectedAt   int    `json:"rejected_at"`
	RejectedWhy  string `json:"rejected_why"`
	Head         string `json:"head"`
}

// ImportBag replays an exported journal bag onto this node. The whole bag is
// validated before any write: it must continue the local chain (or be a full
// seed bag), its internal hash chain must be intact, and every packet's
// signature must verify against the local subscriber registry (identical
// operator keypairs are provisioned on every node). Bags that were already
// ingested are skipped idempotently via the deterministic packet id.
func (h *Hub) ImportBag(ctx context.Context, entries []db.JournalEntry) (ImportReport, error) {
	r := ImportReport{RejectedAt: -1}
	if len(entries) == 0 {
		head, _ := h.st.JournalHead(ctx)
		r.Head = head
		return r, nil
	}

	ex, err := h.st.PacketExists(ctx, entries[0].ID)
	if err != nil {
		return r, err
	}
	if ex {
		r.SkippedDup = len(entries)
		head, _ := h.st.JournalHead(ctx)
		r.Head = head
		return r, nil
	}

	head, err := h.st.JournalHead(ctx)
	if err != nil {
		return r, err
	}
	if head != entries[0].PrevHash {
		r.Rejected, r.RejectedAt, r.RejectedWhy = true, 0,
			"bag does not continue this node's journal chain (local head differs); import into an empty node or the immediate successor of the previous bag"
		return r, nil
	}
	if bad := db.VerifyBag(entries); bad >= 0 {
		r.Rejected, r.RejectedAt, r.RejectedWhy = true, bad, "bag internal hash chain is broken at this index"
		return r, nil
	}

	// Signature check against local pubkeys. Revoked callers still verify their
	// pre-revocation packets, so an imported CRL bag converges cleanly.
	ver := &protocol.Verifier{Subs: func(ctx context.Context, callsign string) (string, string, error) {
		sub, err := h.st.SubscriberByCallsign(ctx, callsign)
		if err != nil {
			return "", "", err
		}
		return sub.PubKey, sub.Role, nil
	}}
	for i, e := range entries {
		f := entryFrame(e)
		if _, err := ver.VerifyStored(ctx, f.Envelope()); err != nil {
			r.Rejected, r.RejectedAt, r.RejectedWhy = true, i,
				"signature does not verify against the local registry: "+err.Error()
			return r, nil
		}
	}

	for i, e := range entries {
		role, _ := ver.Role(ctx, e.Sender)
		appended, ctxSkipped, err := h.replayImport(ctx, e, role)
		if err != nil {
			log.Printf("import row %d (%s by %s): %v", i, e.Kind, e.Sender, err)
		}
		if appended {
			r.AddedJournal++
		}
		if ctxSkipped {
			r.SkippedCtx++
		}
	}
	head, _ = h.st.JournalHead(ctx)
	r.Head = head
	return r, nil
}

// entryFrame rebuilds the original signed frame from a stored journal row.
func entryFrame(e db.JournalEntry) protocol.Frame {
	return protocol.Frame{
		Sender:    e.Sender,
		TS:        e.TS,
		Nonce:     e.Nonce,
		Kind:      e.Kind,
		Signature: e.Signature,
		Data:      json.RawMessage(e.Payload),
	}
}

// replayImport applies one journal row's side effects (locations, messages,
// alarms, zones, CRL) and appends the audit row. appended reports whether the
// row entered the local journal; ctxSkipped reports a side effect that could
// not be applied because its target object is absent locally (the row itself is
// still journaled, so the audit trail converges completely).
func (h *Hub) replayImport(ctx context.Context, e db.JournalEntry, role string) (appended, ctxSkipped bool, err error) {
	f := entryFrame(e)
	switch e.Kind {
	case "marker":
		_, err = h.IngestMarker(ctx, f)
	case "marker_update":
		_, err = h.IngestMarkerUpdate(ctx, f)
	case "marker_delete":
		err = h.IngestMarkerDelete(ctx, f, role)
	case "message":
		_, err = h.IngestMessage(ctx, f)
	case "alert":
		_, err = h.IngestAlert(ctx, f)
	case "alert_ack":
		_, err = h.IngestAlertAck(ctx, f)
	case "alert_clear":
		_, err = h.IngestAlertClear(ctx, f, role)
	case "zone":
		_, err = h.IngestZone(ctx, f)
	case "zone_update":
		_, err = h.IngestZoneUpdate(ctx, f)
	case "zone_delete":
		err = h.IngestZoneDelete(ctx, f, role)
	case "revoke_subscriber", "unrevoke_subscriber":
		err = h.replayRevoke(ctx, f, role)
		return err == nil, false, err
	default:
		h.journal(ctx, f, e.Recipient)
		return true, false, nil
	}
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			h.journal(ctx, f, e.Recipient)
			return true, true, nil
		}
		return false, false, err
	}
	return true, false, nil
}

// replayRevoke applies a CRL entry to the local subscriber registry and keeps
// the audit row. A target that is unknown on this node causes no side effect,
// but the row is still journaled so chains stay identical across nodes.
func (h *Hub) replayRevoke(ctx context.Context, f protocol.Frame, role string) error {
	if role != "admin" {
		return errors.New("revoke/unrevoke requires an admin signer")
	}
	var m struct {
		Callsign string `json:"callsign"`
	}
	if err := json.Unmarshal(f.Data, &m); err != nil || m.Callsign == "" {
		return errors.New("revoke/unrevoke entry: callsign required")
	}
	apply := h.st.RevokeSubscriber
	if f.Kind == "unrevoke_subscriber" {
		apply = h.st.UnrevokeSubscriber
	}
	if err := apply(ctx, m.Callsign); err != nil && !errors.Is(err, db.ErrNotFound) {
		return err
	}
	h.MarkRevoked(m.Callsign, f.Kind == "revoke_subscriber")
	h.journal(ctx, f, "@system")
	return nil
}
