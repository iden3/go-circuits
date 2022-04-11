package circuits

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

// TypedInputs is inputs that can be validated in the specific circuit
type TypedInputs interface {
	Validate(schema []byte) error
}
