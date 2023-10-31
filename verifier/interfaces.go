package verifier

import (
	"context"
	"encoding/json"
	"math/big"

	"github.com/iden3/go-circuits/v2"
	"github.com/piprate/json-gold/ld"
)

// Verifier is interface for verification of public signals of zkp
type Verifier interface {
	VerifyQuery(ctx context.Context, query Query, schemaLoader ld.DocumentLoader, verifiablePresentation json.RawMessage, opts ...VerifyOpt) error
	VerifyStates(ctx context.Context, resolvers map[string]StateResolver, opts ...VerifyOpt) error
	VerifyIDOwnership(userIdentifier string, challenge *big.Int) error

	circuits.PubSignalsUnmarshaller
}

// StateResolver is a state resolver interface
type StateResolver interface {
	Resolve(ctx context.Context, id *big.Int, state *big.Int) (*ResolvedState, error)
	ResolveGlobalRoot(ctx context.Context, state *big.Int) (*ResolvedState, error)
}

// ResolvedState can be the state verification result
type ResolvedState struct {
	State               string `json:"state"`
	Latest              bool   `json:"latest"`
	Genesis             bool   `json:"genesis"`
	TransitionTimestamp int64  `json:"transition_timestamp"`
}
