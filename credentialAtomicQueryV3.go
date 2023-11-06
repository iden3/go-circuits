package circuits

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/pkg/errors"
)

type ProofType string

const (
	SigProotType ProofType = "sig"
	MTPProofType ProofType = "mtp"
)

// AtomicQueryV3Inputs ZK private inputs for credentialAtomicQuerySig.circom
type AtomicQueryV3Inputs struct {
	BaseConfig

	RequestID *big.Int

	// auth
	ID                       *core.ID
	ProfileNonce             *big.Int
	ClaimSubjectProfileNonce *big.Int

	Claim                    ClaimWithSigAndMTPProof
	SkipClaimRevocationCheck bool

	// query
	Query Query

	CurrentTimeStamp int64

	ProofType ProofType

	LinkNonce *big.Int

	VerifierID *core.ID

	VerifierSessionID *big.Int
}

// atomicQueryV3CircuitInputs type represents credentialAtomicQueryV3.circom private inputs required by prover
type atomicQueryV3CircuitInputs struct {
	RequestID string `json:"requestID"`

	// user data
	UserGenesisID            string `json:"userGenesisID"`
	ProfileNonce             string `json:"profileNonce"`
	ClaimSubjectProfileNonce string `json:"claimSubjectProfileNonce"`

	IssuerID string `json:"issuerID"`
	// Claim
	IssuerClaim                     *core.Claim      `json:"issuerClaim"`
	IssuerClaimNonRevClaimsTreeRoot string           `json:"issuerClaimNonRevClaimsTreeRoot"`
	IssuerClaimNonRevRevTreeRoot    string           `json:"issuerClaimNonRevRevTreeRoot"`
	IssuerClaimNonRevRootsTreeRoot  string           `json:"issuerClaimNonRevRootsTreeRoot"`
	IssuerClaimNonRevState          string           `json:"issuerClaimNonRevState"`
	IssuerClaimNonRevMtp            []string         `json:"issuerClaimNonRevMtp"`
	IssuerClaimNonRevMtpAuxHi       *merkletree.Hash `json:"issuerClaimNonRevMtpAuxHi"`
	IssuerClaimNonRevMtpAuxHv       *merkletree.Hash `json:"issuerClaimNonRevMtpAuxHv"`
	IssuerClaimNonRevMtpNoAux       string           `json:"issuerClaimNonRevMtpNoAux"`
	ClaimSchema                     string           `json:"claimSchema"`
	IssuerClaimSignatureR8X         string           `json:"issuerClaimSignatureR8x"`
	IssuerClaimSignatureR8Y         string           `json:"issuerClaimSignatureR8y"`
	IssuerClaimSignatureS           string           `json:"issuerClaimSignatureS"`
	IssuerAuthClaim                 *core.Claim      `json:"issuerAuthClaim"`
	IssuerAuthClaimMtp              []string         `json:"issuerAuthClaimMtp"`
	IssuerAuthClaimNonRevMtp        []string         `json:"issuerAuthClaimNonRevMtp"`
	IssuerAuthClaimNonRevMtpAuxHi   *merkletree.Hash `json:"issuerAuthClaimNonRevMtpAuxHi"`
	IssuerAuthClaimNonRevMtpAuxHv   *merkletree.Hash `json:"issuerAuthClaimNonRevMtpAuxHv"`
	IssuerAuthClaimNonRevMtpNoAux   string           `json:"issuerAuthClaimNonRevMtpNoAux"`
	IssuerAuthClaimsTreeRoot        string           `json:"issuerAuthClaimsTreeRoot"`
	IssuerAuthRevTreeRoot           string           `json:"issuerAuthRevTreeRoot"`
	IssuerAuthRootsTreeRoot         string           `json:"issuerAuthRootsTreeRoot"`

	IsRevocationChecked int `json:"isRevocationChecked"`
	// Query
	// JSON path
	ClaimPathNotExists int              `json:"claimPathNotExists"` // 0 for inclusion, 1 for non-inclusion
	ClaimPathMtp       []string         `json:"claimPathMtp"`
	ClaimPathMtpNoAux  string           `json:"claimPathMtpNoAux"` // 1 if aux node is empty, 0 if non-empty or for inclusion proofs
	ClaimPathMtpAuxHi  *merkletree.Hash `json:"claimPathMtpAuxHi"` // 0 for inclusion proof
	ClaimPathMtpAuxHv  *merkletree.Hash `json:"claimPathMtpAuxHv"` // 0 for inclusion proof
	ClaimPathKey       string           `json:"claimPathKey"`      // hash of path in merklized json-ld document
	ClaimPathValue     string           `json:"claimPathValue"`    // value in this path in merklized json-ld document

	Operator  int      `json:"operator"`
	SlotIndex int      `json:"slotIndex"`
	Timestamp int64    `json:"timestamp"`
	Value     []string `json:"value"`

	IssuerClaimMtp            []*merkletree.Hash `json:"issuerClaimMtp"`
	IssuerClaimClaimsTreeRoot *merkletree.Hash   `json:"issuerClaimClaimsTreeRoot"`
	IssuerClaimRevTreeRoot    *merkletree.Hash   `json:"issuerClaimRevTreeRoot"`
	IssuerClaimRootsTreeRoot  *merkletree.Hash   `json:"issuerClaimRootsTreeRoot"`
	IssuerClaimIdenState      *merkletree.Hash   `json:"issuerClaimIdenState"`

	ProofType string `json:"proofType"`

	// Private random nonce, used to generate LinkID
	LinkNonce string `json:"linkNonce"`

	VerifierID string `json:"verifierID"`

	VerifierSessionID string `json:"verifierSessionID"`
}

func (a AtomicQueryV3Inputs) Validate() error {

	if a.RequestID == nil {
		return errors.New(ErrorEmptyRequestID)
	}

	if a.Claim.NonRevProof.Proof == nil {
		return errors.New(ErrorEmptyClaimNonRevProof)
	}

	if a.Query.Values == nil {
		return errors.New(ErrorEmptyQueryValue)
	}

	switch a.ProofType {
	case SigProotType:
		if a.Claim.SignatureProof.IssuerAuthIncProof.Proof == nil {
			return errors.New(ErrorEmptyIssuerAuthClaimProof)
		}

		if a.Claim.SignatureProof.IssuerAuthNonRevProof.Proof == nil {
			return errors.New(ErrorEmptyIssuerAuthClaimNonRevProof)
		}

		if a.Claim.SignatureProof.Signature == nil {
			return errors.New(ErrorEmptyClaimSignature)
		}
	case MTPProofType:
		if a.Claim.IncProof.Proof == nil {
			return errors.New(ErrorEmptyClaimProof)
		}
	default:
		return errors.New(ErrorInvalidProofType)
	}

	return nil
}

// InputsMarshal returns Circom private inputs for credentialAtomicQueryV3.circom
func (a AtomicQueryV3Inputs) InputsMarshal() ([]byte, error) {

	if err := a.Validate(); err != nil {
		return nil, err
	}

	if a.Query.ValueProof != nil {
		if err := a.Query.validate(); err != nil {
			return nil, err
		}
		if err := a.Query.ValueProof.validate(); err != nil {
			return nil, err
		}
	}

	valueProof := a.Query.ValueProof

	if valueProof == nil {
		valueProof = &ValueProof{}
		valueProof.Path = big.NewInt(0)
		valueProof.Value = big.NewInt(0)
		valueProof.MTP = &merkletree.Proof{}
	}

	s := atomicQueryV3CircuitInputs{
		RequestID:                a.RequestID.String(),
		UserGenesisID:            a.ID.BigInt().String(),
		ProfileNonce:             a.ProfileNonce.String(),
		ClaimSubjectProfileNonce: a.ClaimSubjectProfileNonce.String(),
		IssuerID:                 a.Claim.IssuerID.BigInt().String(),
		IssuerClaim:              a.Claim.Claim,

		IssuerClaimNonRevClaimsTreeRoot: a.Claim.NonRevProof.TreeState.ClaimsRoot.BigInt().String(),
		IssuerClaimNonRevRevTreeRoot:    a.Claim.NonRevProof.TreeState.RevocationRoot.BigInt().String(),
		IssuerClaimNonRevRootsTreeRoot:  a.Claim.NonRevProof.TreeState.RootOfRoots.BigInt().String(),
		IssuerClaimNonRevState:          a.Claim.NonRevProof.TreeState.State.BigInt().String(),
		IssuerClaimNonRevMtp: PrepareSiblingsStr(a.Claim.NonRevProof.Proof.AllSiblings(),
			a.GetMTLevel()),

		ClaimSchema: a.Claim.Claim.GetSchemaHash().BigInt().String(),

		ClaimPathMtp: PrepareSiblingsStr(valueProof.MTP.AllSiblings(),
			a.GetMTLevelsClaim()),
		ClaimPathValue: valueProof.Value.Text(10),
		Operator:       a.Query.Operator,
		Timestamp:      a.CurrentTimeStamp,
		// value in this path in merklized json-ld document

		SlotIndex:           a.Query.SlotIndex,
		IsRevocationChecked: 1,
	}

	if a.SkipClaimRevocationCheck {
		s.IsRevocationChecked = 0
	}

	switch a.ProofType {
	case SigProotType:
		s.ProofType = "1"

		s.IssuerClaimSignatureR8X = a.Claim.SignatureProof.Signature.R8.X.String()
		s.IssuerClaimSignatureR8Y = a.Claim.SignatureProof.Signature.R8.Y.String()
		s.IssuerClaimSignatureS = a.Claim.SignatureProof.Signature.S.String()
		s.IssuerAuthClaim = a.Claim.SignatureProof.IssuerAuthClaim
		s.IssuerAuthClaimMtp = PrepareSiblingsStr(a.Claim.SignatureProof.IssuerAuthIncProof.Proof.AllSiblings(),
			a.GetMTLevel())
		s.IssuerAuthClaimsTreeRoot = a.Claim.SignatureProof.IssuerAuthIncProof.TreeState.ClaimsRoot.
			BigInt().String()
		s.IssuerAuthRevTreeRoot = a.Claim.SignatureProof.IssuerAuthIncProof.TreeState.RevocationRoot.BigInt().String()
		s.IssuerAuthRootsTreeRoot = a.Claim.SignatureProof.IssuerAuthIncProof.TreeState.RootOfRoots.BigInt().String()
		s.IssuerAuthClaimNonRevMtp = PrepareSiblingsStr(a.Claim.SignatureProof.IssuerAuthNonRevProof.Proof.
			AllSiblings(), a.GetMTLevel())

		nodeAuxIssuerAuthNonRev := GetNodeAuxValue(a.Claim.SignatureProof.IssuerAuthNonRevProof.Proof)
		s.IssuerAuthClaimNonRevMtpAuxHi = nodeAuxIssuerAuthNonRev.key
		s.IssuerAuthClaimNonRevMtpAuxHv = nodeAuxIssuerAuthNonRev.value
		s.IssuerAuthClaimNonRevMtpNoAux = nodeAuxIssuerAuthNonRev.noAux

		a.fillMTPProofsWithZero(&s)
	case MTPProofType:
		s.ProofType = "2"

		s.IssuerClaimMtp = CircomSiblings(a.Claim.IncProof.Proof, a.GetMTLevel())
		s.IssuerClaimClaimsTreeRoot = a.Claim.IncProof.TreeState.ClaimsRoot
		s.IssuerClaimRevTreeRoot = a.Claim.IncProof.TreeState.RevocationRoot
		s.IssuerClaimRootsTreeRoot = a.Claim.IncProof.TreeState.RootOfRoots
		s.IssuerClaimIdenState = a.Claim.IncProof.TreeState.State

		a.fillSigProofWithZero(&s)
	}

	nodeAuxNonRev := GetNodeAuxValue(a.Claim.NonRevProof.Proof)
	s.IssuerClaimNonRevMtpAuxHi = nodeAuxNonRev.key
	s.IssuerClaimNonRevMtpAuxHv = nodeAuxNonRev.value
	s.IssuerClaimNonRevMtpNoAux = nodeAuxNonRev.noAux

	s.ClaimPathNotExists = existenceToInt(valueProof.MTP.Existence)
	nodAuxJSONLD := GetNodeAuxValue(valueProof.MTP)
	s.ClaimPathMtpNoAux = nodAuxJSONLD.noAux
	s.ClaimPathMtpAuxHi = nodAuxJSONLD.key
	s.ClaimPathMtpAuxHv = nodAuxJSONLD.value

	s.ClaimPathKey = valueProof.Path.String()

	values, err := PrepareCircuitArrayValues(a.Query.Values, a.GetValueArrSize())
	if err != nil {
		return nil, err
	}
	s.Value = bigIntArrayToStringArray(values)
	s.LinkNonce = a.LinkNonce.String()

	s.VerifierID = "0"
	if a.VerifierID != nil {
		s.VerifierID = a.VerifierID.BigInt().String()
	}

	s.VerifierSessionID = "0"
	if a.VerifierSessionID != nil {
		s.VerifierSessionID = a.VerifierSessionID.String()
	}

	return json.Marshal(s)
}

func (a AtomicQueryV3Inputs) fillMTPProofsWithZero(s *atomicQueryV3CircuitInputs) {
	s.IssuerClaimMtp = CircomSiblings(&merkletree.Proof{}, a.GetMTLevel())
	s.IssuerClaimClaimsTreeRoot = &merkletree.HashZero
	s.IssuerClaimRevTreeRoot = &merkletree.HashZero
	s.IssuerClaimRootsTreeRoot = &merkletree.HashZero
	s.IssuerClaimIdenState = &merkletree.HashZero
}

func (a AtomicQueryV3Inputs) fillSigProofWithZero(s *atomicQueryV3CircuitInputs) {
	s.IssuerClaimSignatureR8X = "0"
	s.IssuerClaimSignatureR8Y = "0"
	s.IssuerClaimSignatureS = "0"
	s.IssuerAuthClaim = &core.Claim{}
	s.IssuerAuthClaimMtp = PrepareSiblingsStr([]*merkletree.Hash{}, a.GetMTLevel())
	s.IssuerAuthClaimsTreeRoot = "0"
	s.IssuerAuthRevTreeRoot = "0"
	s.IssuerAuthRootsTreeRoot = "0"
	s.IssuerAuthClaimNonRevMtp = PrepareSiblingsStr([]*merkletree.Hash{}, a.GetMTLevel())

	s.IssuerAuthClaimNonRevMtpAuxHi = &merkletree.HashZero
	s.IssuerAuthClaimNonRevMtpAuxHv = &merkletree.HashZero
	s.IssuerAuthClaimNonRevMtpNoAux = "0"
}

// AtomicQueryV3PubSignals public inputs
type AtomicQueryV3PubSignals struct {
	BaseConfig
	RequestID              *big.Int         `json:"requestID"`
	UserID                 *core.ID         `json:"userID"`
	IssuerID               *core.ID         `json:"issuerID"`
	IssuerState            *merkletree.Hash `json:"issuerState"`
	IssuerClaimNonRevState *merkletree.Hash `json:"issuerClaimNonRevState"`
	ClaimSchema            core.SchemaHash  `json:"claimSchema"`
	SlotIndex              int              `json:"slotIndex"`
	Operator               int              `json:"operator"`
	Value                  []*big.Int       `json:"value"`
	Timestamp              int64            `json:"timestamp"`
	Merklized              int              `json:"merklized"`
	ClaimPathKey           *big.Int         `json:"claimPathKey"`
	ClaimPathNotExists     int              `json:"claimPathNotExists"`  // 0 for inclusion, 1 for non-inclusion
	IsRevocationChecked    int              `json:"isRevocationChecked"` // 0 revocation not check, // 1 for check revocation
	ProofType              int              `json:"proofType"`
	LinkID                 *big.Int         `json:"linkID"`
	Nullifier              *big.Int         `json:"nullifier"`
	OperatorOutput         *big.Int         `json:"operatorOutput"`
	VerifierID             *core.ID         `json:"verifierID"`
	VerifierSessionID      *big.Int         `json:"verifierSessionID"`
}

// PubSignalsUnmarshal unmarshal credentialAtomicQueryV3.circom public signals
func (ao *AtomicQueryV3PubSignals) PubSignalsUnmarshal(data []byte) error {
	// expected order:
	// merklized
	// userID
	// issuerState
	// linkID
	// nullifier
	// operatorOutput
	// proofType
	// requestID
	// issuerID
	// isRevocationChecked
	// issuerClaimNonRevState
	// timestamp
	// claimSchema
	// claimPathNotExists
	// claimPathKey
	// slotIndex
	// operator
	// value
	// verifierID
	// verifierSessionID

	// 19 is a number of fields in AtomicQueryV3PubSignals, values length could be
	// different base on the circuit configuration. The length could be modified by set value
	// in ValueArraySize
	const fieldLength = 19

	var sVals []string
	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	if len(sVals) != fieldLength+ao.GetValueArrSize() {
		return fmt.Errorf("invalid number of Output values expected {%d} go {%d} ", fieldLength+ao.GetValueArrSize(), len(sVals))
	}

	fieldIdx := 0

	// -- merklized
	if ao.Merklized, err = strconv.Atoi(sVals[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++

	//  - userID
	if ao.UserID, err = idFromIntStr(sVals[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++

	// - issuerState
	if ao.IssuerState, err = merkletree.NewHashFromString(sVals[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++

	var ok bool
	// - linkID
	if ao.LinkID, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid link ID value: '%s'", sVals[fieldIdx])
	}
	fieldIdx++

	// - nullifier
	if ao.Nullifier, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid link ID value: '%s'", sVals[fieldIdx])
	}
	fieldIdx++

	// - operatorOutput
	if ao.OperatorOutput, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid operator output value: '%s'", sVals[fieldIdx])
	}
	fieldIdx++

	if ao.ProofType, err = strconv.Atoi(sVals[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++

	// - requestID
	if ao.RequestID, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid requestID value: '%s'", sVals[fieldIdx])
	}
	fieldIdx++

	// - issuerID
	if ao.IssuerID, err = idFromIntStr(sVals[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++

	// - isRevocationChecked
	if ao.IsRevocationChecked, err = strconv.Atoi(sVals[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++

	// - issuerClaimNonRevState
	if ao.IssuerClaimNonRevState, err = merkletree.NewHashFromString(sVals[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++

	//  - timestamp
	ao.Timestamp, err = strconv.ParseInt(sVals[fieldIdx], 10, 64)
	if err != nil {
		return err
	}
	fieldIdx++

	//  - claimSchema
	var schemaInt *big.Int
	if schemaInt, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid schema value: '%s'", sVals[0])
	}
	ao.ClaimSchema = core.NewSchemaHashFromInt(schemaInt)
	fieldIdx++

	// - ClaimPathNotExists
	if ao.ClaimPathNotExists, err = strconv.Atoi(sVals[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++

	// - ClaimPathKey
	if ao.ClaimPathKey, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid claimPathKey: %s", sVals[fieldIdx])
	}
	fieldIdx++

	// - slotIndex
	if ao.SlotIndex, err = strconv.Atoi(sVals[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++

	// - operator
	if ao.Operator, err = strconv.Atoi(sVals[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++

	//  - values
	var valuesNum = ao.GetValueArrSize()
	for i := 0; i < valuesNum; i++ {
		bi, ok := big.NewInt(0).SetString(sVals[fieldIdx], 10)
		if !ok {
			return fmt.Errorf("invalid value in index: %d", i)
		}
		ao.Value = append(ao.Value, bi)
		fieldIdx++
	}

	//  - VerifierID
	if sVals[fieldIdx] != "0" {
		if ao.VerifierID, err = idFromIntStr(sVals[fieldIdx]); err != nil {
			return err
		}
	}
	fieldIdx++

	//  - VerifierSessionID
	if ao.VerifierSessionID, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid verifier session ID: %s", sVals[fieldIdx])
	}

	return nil
}

// GetObjMap returns struct field as a map
func (ao AtomicQueryV3PubSignals) GetObjMap() map[string]interface{} {
	return toMap(ao)
}
