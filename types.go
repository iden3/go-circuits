package circuits

import (
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql"
)

// VerificationKeyJSON describes type verification key in JSON format
type VerificationKeyJSON string

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
