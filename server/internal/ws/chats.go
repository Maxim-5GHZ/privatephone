package ws

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"privatephone/server/internal/db"
	"privatephone/server/internal/protocol"
)

func normalizeMembers(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, m := range in {
		c := strings.TrimSpace(strings.ToLower(m))
		if c == "" {
			continue
		}
		if _, ok := seen[c]; ok {
			continue
		}
		if len(c) > 64 {
			continue
		}
		valid := true
		for _, r := range c {
			if r < 32 {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

// IngestChatCreate creates a named channel (admin only). The creator is
// auto-added to members so they can read/write the chat. The chat id is
// derived deterministically from the signed packet (sender|kind|nonce|ts) so
// sneaker-net re-imports deduplicate instead of forking the chat.
func (h *Hub) IngestChatCreate(ctx context.Context, f protocol.Frame, role string) (db.Chat, error) {
	var rec db.Chat
	if role != "admin" {
		return rec, errors.New("admin role required")
	}
	var m struct {
		Name    string   `json:"name"`
		Members []string `json:"members"`
		N       string   `json:"n"`
	}
	if err := json.Unmarshal(f.Data, &m); err != nil {
		return rec, err
	}
	name := strings.TrimSpace(m.Name)
	if name == "" || len(name) > 64 {
		return rec, errors.New("chat name required (1..64 chars)")
	}
	members := normalizeMembers(m.Members)
	// ensure creator is a member
	found := false
	for _, x := range members {
		if x == f.Sender {
			found = true
			break
		}
	}
	if !found {
		members = append(members, f.Sender)
	}
	if len(members) == 0 || len(members) > 64 {
		return rec, errors.New("chat needs 1..64 members")
	}
	id := db.PacketID(f.Sender, f.Kind, f.Nonce, f.TS)
	if err := h.st.CreateChat(ctx, id, name, members, f.Sender); err != nil {
		if errors.Is(err, db.ErrDuplicate) {
			// idempotent replay (sneaker-net / retry): return existing
			if existing, err2 := h.st.ChatByID(ctx, id); err2 == nil {
				return *existing, nil
			}
		}
		return rec, err
	}
	chat, err := h.st.ChatByID(ctx, id)
	if err != nil {
		return rec, err
	}
	rec = *chat
	h.journal(ctx, f, "@system")
	b, _ := json.Marshal(out{Kind: "chat_created", Data: rec})
	h.deliver(b, members, f.Sender)
	return rec, nil
}

// IngestChatUpdate renames a chat and/or replaces members (admin only).
func (h *Hub) IngestChatUpdate(ctx context.Context, f protocol.Frame, role string) (db.Chat, error) {
	var rec db.Chat
	if role != "admin" {
		return rec, errors.New("admin role required")
	}
	var m struct {
		ID      string   `json:"id"`
		Name    string   `json:"name"`
		Members []string `json:"members"`
	}
	if err := json.Unmarshal(f.Data, &m); err != nil {
		return rec, err
	}
	if strings.TrimSpace(m.ID) == "" {
		return rec, errors.New("chat id required")
	}
	name := strings.TrimSpace(m.Name)
	if name == "" || len(name) > 64 {
		return rec, errors.New("chat name required (1..64 chars)")
	}
	members := normalizeMembers(m.Members)
	if len(members) == 0 || len(members) > 64 {
		return rec, errors.New("chat needs 1..64 members")
	}
	updated, err := h.st.UpdateChat(ctx, strings.TrimSpace(m.ID), name, members)
	if err != nil {
		return rec, err
	}
	rec = *updated
	h.journal(ctx, f, "@system")
	b, _ := json.Marshal(out{Kind: "chat_updated", Data: rec})
	h.deliver(b, members, f.Sender)
	// also notify old members that they were removed: broadcast fallback
	// is avoided for privacy; removed members simply stop receiving new events.
	return rec, nil
}

// IngestChatDelete archives a chat (admin only).
func (h *Hub) IngestChatDelete(ctx context.Context, f protocol.Frame, role string) error {
	if role != "admin" {
		return errors.New("admin role required")
	}
	var m struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(f.Data, &m); err != nil {
		return err
	}
	id := strings.TrimSpace(m.ID)
	if id == "" {
		return errors.New("chat id required")
	}
	chat, err := h.st.ChatByID(ctx, id)
	if err != nil {
		return err
	}
	if err := h.st.DeleteChat(ctx, id); err != nil {
		return err
	}
	h.journal(ctx, f, "@system")
	b, _ := json.Marshal(out{Kind: "chat_deleted", Data: map[string]any{"id": id}})
	h.deliver(b, chat.Members, f.Sender)
	return nil
}

// expandMessageRecipients resolves "chat:<id>" to its member list.
func (h *Hub) expandMessageRecipients(ctx context.Context, recipient string) ([]string, error) {
	if strings.HasPrefix(recipient, "chat:") {
		id := strings.TrimPrefix(recipient, "chat:")
		if id == "" {
			return nil, errors.New("bad chat recipient")
		}
		chat, err := h.st.ChatByID(ctx, id)
		if err != nil {
			return nil, errors.New("unknown chat")
		}
		return append([]string{}, chat.Members...), nil
	}
	return parseRecipients(recipient), nil
}

// isChatMember reports whether sender belongs to chat:<id>.
func (h *Hub) isChatMember(ctx context.Context, sender, recipient string) (bool, error) {
	if !strings.HasPrefix(recipient, "chat:") {
		return true, nil
	}
	id := strings.TrimPrefix(recipient, "chat:")
	chat, err := h.st.ChatByID(ctx, id)
	if err != nil {
		return false, err
	}
	for _, m := range chat.Members {
		if m == sender {
			return true, nil
		}
	}
	return false, nil
}
