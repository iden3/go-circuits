package circuits

import (
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql/v2"
)

type ClaimNonRevStatus struct {
	TreeState TreeState         `json:"treeState"`
	Proof     *merkletree.Proof `json:"proof"`
}

type Claim struct {
	IssuerID  *core.ID          `json:"issuerID"`
	Claim     *core.Claim       `json:"claim"`
	TreeState TreeState         `json:"treeState"`
	Proof     *merkletree.Proof `json:"proof"`
	// Claim non revocation proof
	NonRevProof    *ClaimNonRevStatus `json:"nonRevProof"`
	SignatureProof BJJSignatureProof  `json:"signatureProof"`
}

type TreeState struct {
	State          *merkletree.Hash `json:"state"`
	ClaimsRoot     *merkletree.Hash `json:"claimsRoot"`
	RevocationRoot *merkletree.Hash `json:"revocationRoot"`
	RootOfRoots    *merkletree.Hash `json:"rootOfRoots"`
}

type BJJSignatureProof struct {
	IssuerID              *core.ID           `json:"issuerID"`
	Signature             *babyjub.Signature `json:"signature"`
	IssuerTreeState       TreeState          `json:"issuerTreeState"`
	IssuerAuthClaim       *core.Claim        `json:"issuerAuthClaim"`
	IssuerAuthClaimMTP    *merkletree.Proof  `json:"issuerAuthClaimMTP"`
	IssuerAuthNonRevProof ClaimNonRevStatus  `json:"issuerAuthNonRevProof"` // IssuerAuthClaim non revocation proof
}

type ClaimV2 struct {
	Claim          *core.Claim       `json:"claim"`
	NonRevProof    ClaimNonRevStatus `json:"nonRevProof"`
	MTProof        MTProof           `json:"mtProof"`
	SignatureProof BJJSignatureProof `json:"signatureProof"`
	GlobalTree     GlobalTree        `json:"globalTree"`
}

type MTProof struct {
	Proof     *merkletree.Proof `json:"proof"`
	TreeState TreeState         `json:"treeState"`
}

type GlobalTree struct {
	Root  *merkletree.Hash  `json:"root"`
	Proof *merkletree.Proof `json:"proof"`
}
