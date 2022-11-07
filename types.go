package circuits

import (
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql/v2"
)

type ClaimWithSigProof struct {
	IssuerID       *core.ID          `json:"issuerID"`
	Claim          *core.Claim       `json:"claim"`
	NonRevProof    MTProof           `json:"nonRevProof"` // Claim non revocation proof
	SignatureProof BJJSignatureProof `json:"signatureProof"`
}

type ClaimWithMTPProof struct {
	IssuerID    *core.ID    `json:"issuerId"`
	Claim       *core.Claim `json:"claim"`
	IncProof    MTProof     `json:"incProof"`    // proof of inclusion `Claim` to the issuer claims tree
	NonRevProof MTProof     `json:"nonRevProof"` // proof of non revocation of the `Claim` in the issuer revocation tree
}

// BJJSignatureProof is a proof of issuer AuthClaim signature over a claim
type BJJSignatureProof struct {
	// Signature Signing the claim with the private key of the issuer associated with the issuerAuthClaim
	Signature       *babyjub.Signature `json:"signature"`
	IssuerAuthClaim *core.Claim        `json:"issuerAuthClaim"` // issuer AuthClaim
	// IssuerAuthIncProof proof of inclusion of issuer AuthClaim to
	// the issuer claims tree
	IssuerAuthIncProof MTProof `json:"issuerAuthIncProof"`
	// IssuerAuthNonRevProof proof of non revocation of issuer
	// AuthClaim in the issuer the latest state
	IssuerAuthNonRevProof MTProof `json:"issuerAuthNonRevProof"`
}

type MTProof struct {
	Proof     *merkletree.Proof `json:"proof"`     // Proof of inclusion to the Merkle Tree
	TreeState TreeState         `json:"treeState"` // Identity state
}

// TreeState represents the identity state
type TreeState struct {
	State          *merkletree.Hash `json:"state"`          // identity state
	ClaimsRoot     *merkletree.Hash `json:"claimsRoot"`     // claims tree root
	RevocationRoot *merkletree.Hash `json:"revocationRoot"` // revocation tree root
	RootOfRoots    *merkletree.Hash `json:"rootOfRoots"`    // root of roots tree root
}

// GlobalMTProof represents the state of the global identities tree published on the blockchain
type GlobalMTProof struct {
	Root  *merkletree.Hash  `json:"root"`  // global identities tree root
	Proof *merkletree.Proof `json:"proof"` // proof of inclusion or non inclusion of the identity to the global identities tree
}
