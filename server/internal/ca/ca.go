package ca

import (
	"context"

	"privatephone/server/internal/crypto"
	"privatephone/server/internal/db"
)

// Result carries the created subscriber record plus the fresh private key PEM
// that must be written on the operator's USB flash.
type Result struct {
	Subscriber *db.Subscriber
	PrivatePEM string
	PublicPEM  string
}

// Create generates a key pair, stores the public part in the vault and returns
// the private PEM for offline delivery to the operator's flash drive.
func Create(ctx context.Context, st *db.Store, callsign, role string) (*Result, error) {
	id, err := crypto.NewID()
	if err != nil {
		return nil, err
	}
	priv, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	privPEM, err := crypto.PrivateKeyToPEM(priv)
	if err != nil {
		return nil, err
	}
	pubPEM, err := crypto.PublicKeyToPEM(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	if err := st.AddSubscriber(ctx, id, callsign, role, string(pubPEM)); err != nil {
		return nil, err
	}
	sub := &db.Subscriber{ID: id, Callsign: callsign, Role: role, PubKey: string(pubPEM)}
	return &Result{Subscriber: sub, PrivatePEM: string(privPEM), PublicPEM: string(pubPEM)}, nil
}
