package ws

import "privatephone/server/internal/db"

// out is a server->client push message.
type out struct {
	Kind string `json:"kind"`
	Data any    `json:"data"`
}

type outSnap struct {
	Kind string   `json:"kind"`
	Data Snapshot `json:"data"`
}

// SnapshotMessageCap keeps the live snapshot bounded on LAN nodes; older rows
// stay reachable via the history endpoint (and via pending backlog packets).
const SnapshotMessageCap = 300

// Snapshot is the full situation push sent on every hello and after changes.
// Messages carry only the newest slice (see snapshot cap); older rows page via
// the history endpoint. Files ride metadata-only; bytes load on demand.
type Snapshot struct {
	Markers      []db.Marker  `json:"markers"`
	Messages     []db.Message `json:"messages"`
	MessagesMore bool         `json:"messages_more,omitempty"`
	Files        []db.File    `json:"files,omitempty"`
	Alerts       []db.Alert   `json:"alerts"`
	Zones        []db.Zone    `json:"zones"`
	Chats        []db.Chat    `json:"chats,omitempty"`
	Online       []string     `json:"online"`
}

type outPackets struct {
	Kind string  `json:"kind"`
	Data packets `json:"data"`
}

type packets struct {
	Items []db.Packet `json:"items"`
}
