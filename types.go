package circuits

import (
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql/v2"
)

type ClaimNonRevStatus struct {
	TreeState TreeState
	Proof     *merkletree.Proof
}

type Claim struct {
	IssuerID       *core.ID
	Claim          *core.Claim
	TreeState      TreeState
	Proof          *merkletree.Proof
	NonRevProof    *ClaimNonRevStatus // Claim non revocation proof
	SignatureProof BJJSignatureProof
}

type TreeState struct {
	State          *merkletree.Hash
	ClaimsRoot     *merkletree.Hash
	RevocationRoot *merkletree.Hash
	RootOfRoots    *merkletree.Hash
}

type BJJSignatureProof struct {
	IssuerID              *core.ID
	Signature             *babyjub.Signature
	IssuerTreeState       TreeState
	IssuerAuthClaim       *core.Claim
	IssuerAuthClaimMTP    *merkletree.Proof
	IssuerAuthNonRevProof ClaimNonRevStatus // IssuerAuthClaim non revocation proof
}

type ClaimV2 struct {
	Claim          *core.Claim
	NonRevProof    ClaimNonRevStatus
	MTProof        MTProof
	SignatureProof BJJSignatureProof
	GlobalTree     GlobalTree
}

type MTProof struct {
	Proof     *merkletree.Proof
	TreeState TreeState
}

type GlobalTree struct {
	Root  *merkletree.Hash
	Proof *merkletree.Proof
}
