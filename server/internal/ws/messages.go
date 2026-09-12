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

// Snapshot is the full situation push sent on every hello and after changes.
type Snapshot struct {
	Markers  []db.Marker  `json:"markers"`
	Messages []db.Message `json:"messages"`
	Alerts   []db.Alert   `json:"alerts"`
	Zones    []db.Zone    `json:"zones"`
	Online   []string     `json:"online"`
}

type outPackets struct {
	Kind string  `json:"kind"`
	Data packets `json:"data"`
}

type packets struct {
	Items []db.Packet `json:"items"`
}
