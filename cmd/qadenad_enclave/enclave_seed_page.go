package main

// Paged chain->enclave seeding.
//
// Seeding used to be one gRPC call per row.  A state-synced joiner carries roughly ten thousand
// rows in its biggest tables, so it made roughly ten thousand calls per table -- each one a proto
// marshal, a round trip over the unix socket, a handler dispatch and a reply.  SeedStorePage moves
// a run of rows per call instead.
//
// WHAT THIS DOES NOT CHANGE is the important part.  Every row is still handed to the SAME handler
// that served it one at a time, in the same order.  That is not an efficiency compromise, it is the
// point: those handlers do work that the rows themselves do not carry.  SetProtectKey and
// SetRecoverKey decrypt a vshare with a historical interval key and build derived indexes from the
// plaintext; SeedCredential maintains the PCXY index.  Writing the rows straight into the store
// would be far faster and would silently skip all of it -- which is precisely how CredentialPCXY
// ended up 972 rows short, and why SeedCredential exists at all.
//
// So the win here is transport and dispatch, and only that.  The per-row handler cost is untouched
// and, for the two key tables, still dominates.  Anyone measuring this should expect the big
// improvement on Wallet/Credential/PublicKey and a modest one on ProtectKey/RecoverKey.

import (
	"context"
	"fmt"

	dsvstypes "github.com/c3qtech/qadena_v3/x/dsvs/types"
	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

// storeHashKeys is the canonical list of mirrored stores, in the ONLY order they may be seeded in.
//
// THE ORDER IS LOAD-BEARING, which is why this is a slice and not the map below.  EnclaveIdentity
// and IntervalPublicKeyID come first because ProtectKey and RecoverKey rows cannot be applied
// without them: their handlers decrypt a vshare with a historical interval key, which means finding
// a peer that holds it and authenticating to that peer.  Seeded in the wrong order the enclave
// reports "couldn't find an active enclave identity for uniqueID" and comes up permanently short of
// those rows plus the private indexes their handlers build.
//
// AuthorizedSignatory belongs to dsvs, which hashes and seeds it through its own keeper.  It is
// listed here because GetStoreHash answers for it; it deliberately has no entry in seedHandlers.
var storeHashKeys = []string{
	types.EnclaveIdentityKeyPrefix,
	types.IntervalPublicKeyIDKeyPrefix,
	types.WalletKeyPrefix,
	types.CredentialKeyPrefix,
	types.JarRegulatorKeyPrefix,
	types.PioneerJarKeyPrefix,
	types.PublicKeyKeyPrefix,
	types.ProtectKeyKeyPrefix,
	types.RecoverKeyKeyPrefix,
	dsvstypes.AuthorizedSignatoryKeyPrefix,
}

// seedRowHandler applies one marshalled row.  Split out per store so the dispatch table below stays
// a table -- the unmarshal target is the only thing that varies.
type seedRowHandler func(ctx context.Context, s *qadenaServer, row []byte) error

// seedRow unmarshals into T and calls that store's existing handler.  Generic over the row type so
// each entry in the table is one line and cannot accidentally pair a type with the wrong handler.
func seedRow[T any, PT interface {
	*T
	Unmarshal([]byte) error
}](apply func(context.Context, *qadenaServer, PT) error) seedRowHandler {
	return func(ctx context.Context, s *qadenaServer, row []byte) error {
		var v T
		if err := PT(&v).Unmarshal(row); err != nil {
			return err
		}
		return apply(ctx, s, PT(&v))
	}
}

// seedHandlers maps a mirrored store to the handler its rows must go through.  The keys are the
// same identifiers GetStoreHash reports, so a store that gains a hash but not an entry here fails
// loudly on its first page rather than seeding into nothing.
var seedHandlers = map[string]seedRowHandler{
	types.WalletKeyPrefix: seedRow(func(ctx context.Context, s *qadenaServer, v *types.Wallet) error {
		_, err := s.SetWallet(ctx, v)
		return err
	}),
	// SEED, not Set: the PCXY index has to be rebuilt from whether a credential HAS a commitment,
	// not from whether it is still unclaimed.  See item 39.
	types.CredentialKeyPrefix: seedRow(func(ctx context.Context, s *qadenaServer, v *types.Credential) error {
		_, err := s.SeedCredential(ctx, v)
		return err
	}),
	types.PublicKeyKeyPrefix: seedRow(func(ctx context.Context, s *qadenaServer, v *types.PublicKey) error {
		_, err := s.SetPublicKey(ctx, v)
		return err
	}),
	types.PioneerJarKeyPrefix: seedRow(func(ctx context.Context, s *qadenaServer, v *types.PioneerJar) error {
		_, err := s.SetPioneerJar(ctx, v)
		return err
	}),
	types.JarRegulatorKeyPrefix: seedRow(func(ctx context.Context, s *qadenaServer, v *types.JarRegulator) error {
		_, err := s.SetJarRegulator(ctx, v)
		return err
	}),
	types.IntervalPublicKeyIDKeyPrefix: seedRow(func(ctx context.Context, s *qadenaServer, v *types.IntervalPublicKeyID) error {
		_, err := s.SetIntervalPublicKeyID(ctx, v)
		return err
	}),
	types.ProtectKeyKeyPrefix: seedRow(func(ctx context.Context, s *qadenaServer, v *types.ProtectKey) error {
		_, err := s.SetProtectKey(ctx, v)
		return err
	}),
	types.RecoverKeyKeyPrefix: seedRow(func(ctx context.Context, s *qadenaServer, v *types.RecoverKey) error {
		_, err := s.SetRecoverKey(ctx, v)
		return err
	}),
	types.EnclaveIdentityKeyPrefix: seedRow(func(ctx context.Context, s *qadenaServer, v *types.EnclaveIdentity) error {
		_, err := s.SetEnclaveIdentity(ctx, v)
		return err
	}),
}

// SeedStorePage applies one page of rows for a single mirrored store.
//
// Rejections are counted and reporting continues to the end of the page.  Stopping at the first
// failure would make the caller's picture of what is missing depend on where in the page the first
// bad row happened to sit; the caller refuses to proceed on any non-zero count either way, so the
// complete tally is strictly more useful.
//
// An UNKNOWN KEY IS AN ERROR, not a skip.  A silent skip here would look exactly like a successful
// seed and leave the store empty -- the same shape of failure this whole path exists to prevent.
func (s *qadenaServer) SeedStorePage(ctx context.Context, in *types.MsgSeedStorePage) (*types.SeedStorePageReply, error) {
	handler, ok := seedHandlers[in.GetKey()]
	if !ok {
		return nil, fmt.Errorf("SeedStorePage: no seed handler for store %q -- "+
			"it is reported by GetStoreHash but cannot be seeded, so it would silently stay empty", in.GetKey())
	}

	reply := &types.SeedStorePageReply{}
	for _, row := range in.GetRows() {
		if err := handler(ctx, s, row); err != nil {
			// Logged per row: the count alone would not say WHICH rows, and for ProtectKey and
			// RecoverKey the reason is usually an unreachable owner rather than the row itself.
			c.LoggerError(logger, "SeedStorePage: rejected a row of "+in.GetKey()+": "+err.Error())
			reply.Failed++
			continue
		}
		reply.Accepted++
	}
	return reply, nil
}
