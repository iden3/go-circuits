package circuits

import (
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql/v2"
)

type ClaimWithSigProof struct {
	IssuerID       *core.ID
	Claim          *core.Claim
	NonRevProof    MTProof // Claim non revocation proof
	SignatureProof BJJSignatureProof
}

type ClaimWithMTPProof struct {
	IssuerID    *core.ID
	Claim       *core.Claim
	MTProof     MTProof
	NonRevProof MTProof // Claim non revocation proof
}

type ClaimWithGlobalAuthProof struct {
	Claim          *core.Claim       `json:"claim"`
	NonRevProof    MTProof           `json:"nonRevProof"`
	MTProof        MTProof           `json:"mtProof"`
	SignatureProof BJJSignatureProof `json:"signatureProof"`
	GlobalTree     GlobalTree        `json:"globalTree"`
}

type BJJSignatureProof struct {
	Signature             *babyjub.Signature `json:"signature"`
	IssuerAuthClaim       *core.Claim        `json:"issuerAuthClaim"`
	IssuerAuthClaimMTP    MTProof            `json:"issuerAuthClaimMTP"`
	IssuerAuthNonRevProof MTProof            `json:"issuerAuthNonRevProof"` // IssuerAuthClaim non revocation proof
}

type MTProof struct {
	Proof     *merkletree.Proof `json:"proof"`
	TreeState TreeState         `json:"treeState"`
}

type TreeState struct {
	State          *merkletree.Hash `json:"state"`
	ClaimsRoot     *merkletree.Hash `json:"claimsRoot"`
	RevocationRoot *merkletree.Hash `json:"revocationRoot"`
	RootOfRoots    *merkletree.Hash `json:"rootOfRoots"`
}

type GlobalTree struct {
	Root  *merkletree.Hash  `json:"root"`
	Proof *merkletree.Proof `json:"proof"`
}
