package circuits

import (
	"math/big"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql"
)

// VerificationKeyJSON describes type verification key in JSON format
type VerificationKeyJSON string

// PublicSchemaJSON is a schema for public signals of circuit
type PublicSchemaJSON string

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

//type CircuitMarshaler interface {
//	CircuitMarshal
//}

// TypedInputs is inputs that can be validated in the specific circuit
type TypedInputs interface {
	Validate(schema []byte) error
	//CircuitMarshaler
}

type Claim struct {
	Claim            *core.Claim
	Schema           core.SchemaHash
	Slots            []*big.Int
	Proof            Proof
	TreeState        TreeState
	CurrentTimeStamp int64
	IssuerID         *core.ID
	AProof           *merkletree.Proof
}

type TreeState struct {
	State          *merkletree.Hash
	ClaimsRoot     *merkletree.Hash
	RevocationRoot *merkletree.Hash
	RootOfRoots    *merkletree.Hash
}

// TODO: remove
type NodeAux struct {
	HIndex *merkletree.Hash
	HValue *merkletree.Hash
}

// TODO: remove
type Proof struct {
	Siblings []*merkletree.Hash
	NodeAux  *NodeAux
}
