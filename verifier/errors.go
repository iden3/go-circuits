package verifier

import "github.com/pkg/errors"

var (
	// ErrGlobalStateIsNotValid invalid global state id.
	ErrGlobalStateIsNotValid = errors.New("global state is not valid")
	// ErrIssuerClaimStateIsNotValid declares that issuer state is invalid.
	ErrIssuerClaimStateIsNotValid = errors.New("issuer state is not valid")
	// ErrIssuerNonRevocationClaimStateIsNotValid declares that issuer non-revocation state is invalid.
	ErrIssuerNonRevocationClaimStateIsNotValid = errors.New("issuer state for non-revocation proofs is not valid")
	// ErrProofGenerationOutdated declares that generated proof is outdated.
	ErrProofGenerationOutdated = errors.New("generated proof is outdated")
	// ErrWronProofType declares that query proof type doesn't match circuit proof type
	ErrWronProofType = errors.New("invalid proof type")
)
