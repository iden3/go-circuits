package circuits

import (
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql"
)

// VerificationKeyJSON describes type verification key in JSON format
type VerificationKeyJSON string

// CircuitID is alias for circuit identifier
type CircuitID string

const (
	// AuthCircuitID is a type that must be used for auth circuit id definition
	AuthCircuitID CircuitID = "auth"
	// KycBySignaturesCircuitID is a type that must be used for kycBySignatures circuit id definition
	KycBySignaturesCircuitID CircuitID = "kycBySignatures"
	// KycCircuitCircuitID is a type that must be used for kyc circuit id definition
	KycCircuitCircuitID CircuitID = "kyc"
	// StateTransitionCircuitID is a type that must be used for idState circuit definition
	StateTransitionCircuitID CircuitID = "stateTransition"
	// AtomicQueryMTPCircuitID is a type for credentialAtomicQueryMTP.circom
	AtomicQueryMTPCircuitID CircuitID = "credentialAtomicQueryMTP"
	// AtomicQuerySigCircuitID is a type for credentialAttrQuerySig.circom
	AtomicQuerySigCircuitID CircuitID = "credentialAtomicQuerySig"
	// AtomicQueryMTPCircuitID is a type for credentialAtomicQueryMTPWithRelay.circom
	AtomicQueryMTPWithRelayCircuitID CircuitID = "credentialAtomicQueryMTPWithRelay"
	// AtomicQuerySigCircuitID is a type for credentialAttrQuerySigWithRelay.circom
	AtomicQuerySigWithRelayCircuitID CircuitID = "credentialAtomicQuerySigWithRelay"
)

type CircuitMarshaller interface {
	CircuitMarshal() ([]byte, error)
}

type ClaimNonRevStatus struct {
	TreeState TreeState
	Proof     *merkletree.Proof
}

type Claim struct {
	Claim          *core.Claim
	TreeState      TreeState
	IssuerID       *core.ID
	Proof          *merkletree.Proof
	NonRevProof    ClaimNonRevStatus // Claim non revocation proof
	SignatureProof BJJSignatureProof
}

type TreeState struct {
	State          *merkletree.Hash
	ClaimsRoot     *merkletree.Hash
	RevocationRoot *merkletree.Hash
	RootOfRoots    *merkletree.Hash
}

type SignatureProof interface {
	signatureProofMarker()
}

type BaseSignatureProof struct {
	IssuerID           *core.ID
	IssuerTreeState    TreeState
	AuthClaimIssuerMTP *merkletree.Proof
}

type BJJSignatureProof struct {
	BaseSignatureProof
	IssuerPublicKey *babyjub.PublicKey
	Signature       *babyjub.Signature
	HIndex          *merkletree.Hash
	HValue          *merkletree.Hash
}

func (BJJSignatureProof) signatureProofMarker() {}
