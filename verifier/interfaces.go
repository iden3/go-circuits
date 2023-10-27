package verifier

import (
	"context"
	"encoding/json"
	"math/big"
	"time"

	"github.com/iden3/go-circuits/v2"
	"github.com/piprate/json-gold/ld"
)

var (
	defaultAuthVerifyOpts  = VerifyConfig{acceptedStateTransitionDelay: time.Minute * 5}
	defaultProofVerifyOpts = VerifyConfig{acceptedStateTransitionDelay: time.Hour,
		acceptedProofGenerationDelay: time.Hour * 24}
)

// Verifier is interface for verification of public signals of zkp
type Verifier interface {
	VerifyQuery(ctx context.Context, query Query, schemaLoader ld.DocumentLoader, verifiablePresentation json.RawMessage, opts ...VerifyOpt) error
	VerifyStates(ctx context.Context, resolvers map[string]StateResolver, opts ...VerifyOpt) error
	VerifyIDOwnership(userIdentifier string, challenge *big.Int) error

	circuits.PubSignalsUnmarshaller
}

// VerifyOpt sets options.
type VerifyOpt func(v *VerifyConfig)

// VerifyConfig verifiers options.
type VerifyConfig struct {
	// is the period of time that a revoked state remains valid.
	acceptedStateTransitionDelay time.Duration
	acceptedProofGenerationDelay time.Duration
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
