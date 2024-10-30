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

// AtomicQueryMTPV2Inputs ZK private inputs for credentialAtomicQueryMTPV2.circom
type AtomicQueryMTPV2Inputs struct {
	BaseConfig
	// auth
	ID                       *core.ID
	ProfileNonce             *big.Int
	ClaimSubjectProfileNonce *big.Int

	Claim                    ClaimWithMTPProof // claim issued for user
	SkipClaimRevocationCheck bool

	RequestID *big.Int

	CurrentTimeStamp int64

	// query
	Query
}

// stateTransitionInputsInternal type represents credentialAtomicQueryMTP.circom private inputs required by prover
type atomicQueryMTPV2CircuitInputs struct {
	RequestID string `json:"requestID"`

	// user data
	UserGenesisID            string `json:"userGenesisID"`            //
	ProfileNonce             string `json:"profileNonce"`             //
	ClaimSubjectProfileNonce string `json:"claimSubjectProfileNonce"` //

	IssuerID string `json:"issuerID"`
	// Claim
	IssuerClaim *core.Claim `json:"issuerClaim"`
	// Inclusion
	IssuerClaimMtp            []*merkletree.Hash `json:"issuerClaimMtp"`
	IssuerClaimClaimsTreeRoot *merkletree.Hash   `json:"issuerClaimClaimsTreeRoot"`
	IssuerClaimRevTreeRoot    *merkletree.Hash   `json:"issuerClaimRevTreeRoot"`
	IssuerClaimRootsTreeRoot  *merkletree.Hash   `json:"issuerClaimRootsTreeRoot"`
	IssuerClaimIdenState      *merkletree.Hash   `json:"issuerClaimIdenState"`

	IssuerClaimNonRevClaimsTreeRoot *merkletree.Hash   `json:"issuerClaimNonRevClaimsTreeRoot"`
	IssuerClaimNonRevRevTreeRoot    *merkletree.Hash   `json:"issuerClaimNonRevRevTreeRoot"`
	IssuerClaimNonRevRootsTreeRoot  *merkletree.Hash   `json:"issuerClaimNonRevRootsTreeRoot"`
	IssuerClaimNonRevState          *merkletree.Hash   `json:"issuerClaimNonRevState"`
	IssuerClaimNonRevMtp            []*merkletree.Hash `json:"issuerClaimNonRevMtp"`
	IssuerClaimNonRevMtpAuxHi       *merkletree.Hash   `json:"issuerClaimNonRevMtpAuxHi"`
	IssuerClaimNonRevMtpAuxHv       *merkletree.Hash   `json:"issuerClaimNonRevMtpAuxHv"`
	IssuerClaimNonRevMtpNoAux       string             `json:"issuerClaimNonRevMtpNoAux"`

	IsRevocationChecked int `json:"isRevocationChecked"`

	ClaimSchema string `json:"claimSchema"`

	// Query
	// JSON path
	ClaimPathNotExists int                `json:"claimPathNotExists"` // 0 for inclusion, 1 for non-inclusion
	ClaimPathMtp       []*merkletree.Hash `json:"claimPathMtp"`
	ClaimPathMtpNoAux  string             `json:"claimPathMtpNoAux"` // 1 if aux node is empty,
	// 0 if non-empty or for inclusion proofs
	ClaimPathMtpAuxHi *merkletree.Hash `json:"claimPathMtpAuxHi"` // 0 for inclusion proof
	ClaimPathMtpAuxHv *merkletree.Hash `json:"claimPathMtpAuxHv"` // 0 for inclusion proof
	ClaimPathKey      string           `json:"claimPathKey"`      // hash of path in merklized json-ld document
	ClaimPathValue    string           `json:"claimPathValue"`    // value in this path in merklized json-ld document

	Operator  int      `json:"operator"`
	SlotIndex int      `json:"slotIndex"`
	Timestamp int64    `json:"timestamp"`
	Value     []string `json:"value"`
}

// Validate validates AtomicQueryMTPPubSignals
func (a AtomicQueryMTPV2Inputs) Validate() error {

	if a.RequestID == nil {
		return errors.New(ErrorEmptyRequestID)
	}

	return nil
}

// InputsMarshal returns Circom private inputs for credentialAtomicQueryMTP.circom
func (a AtomicQueryMTPV2Inputs) InputsMarshal() ([]byte, error) {
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

	s := atomicQueryMTPV2CircuitInputs{
		RequestID:                       a.RequestID.String(),
		UserGenesisID:                   a.ID.BigInt().String(),
		ProfileNonce:                    a.ProfileNonce.String(),
		ClaimSubjectProfileNonce:        a.ClaimSubjectProfileNonce.String(),
		IssuerID:                        a.Claim.IssuerID.BigInt().String(),
		IssuerClaim:                     a.Claim.Claim,
		IssuerClaimMtp:                  CircomSiblings(a.Claim.IncProof.Proof, a.GetMTLevel()),
		IssuerClaimClaimsTreeRoot:       a.Claim.IncProof.TreeState.ClaimsRoot,
		IssuerClaimRevTreeRoot:          a.Claim.IncProof.TreeState.RevocationRoot,
		IssuerClaimRootsTreeRoot:        a.Claim.IncProof.TreeState.RootOfRoots,
		IssuerClaimIdenState:            a.Claim.IncProof.TreeState.State,
		IssuerClaimNonRevMtp:            CircomSiblings(a.Claim.NonRevProof.Proof, a.GetMTLevel()),
		IssuerClaimNonRevClaimsTreeRoot: a.Claim.NonRevProof.TreeState.ClaimsRoot,
		IssuerClaimNonRevRevTreeRoot:    a.Claim.NonRevProof.TreeState.RevocationRoot,
		IssuerClaimNonRevRootsTreeRoot:  a.Claim.NonRevProof.TreeState.RootOfRoots,
		IssuerClaimNonRevState:          a.Claim.NonRevProof.TreeState.State,
		ClaimSchema:                     a.Claim.Claim.GetSchemaHash().BigInt().String(),
		ClaimPathMtp:                    CircomSiblings(valueProof.MTP, a.GetMTLevelsClaim()),
		ClaimPathValue:                  valueProof.Value.String(),
		Operator:                        a.Operator,
		SlotIndex:                       a.SlotIndex,
		Timestamp:                       a.CurrentTimeStamp,
		IsRevocationChecked:             1,
	}

	if a.SkipClaimRevocationCheck {
		s.IsRevocationChecked = 0
	}

	nodeAux := GetNodeAuxValue(a.Claim.NonRevProof.Proof)
	s.IssuerClaimNonRevMtpAuxHi = nodeAux.key
	s.IssuerClaimNonRevMtpAuxHv = nodeAux.value
	s.IssuerClaimNonRevMtpNoAux = nodeAux.noAux

	s.ClaimPathNotExists = existenceToInt(valueProof.MTP.Existence)
	nodAuxJSONLD := GetNodeAuxValue(valueProof.MTP)
	s.ClaimPathMtpNoAux = nodAuxJSONLD.noAux
	s.ClaimPathMtpAuxHi = nodAuxJSONLD.key
	s.ClaimPathMtpAuxHv = nodAuxJSONLD.value

	s.ClaimPathKey = valueProof.Path.String()

	values, err := PrepareCircuitArrayValues(a.Values, a.GetValueArrSize())
	if err != nil {
		return nil, err
	}
	s.Value = bigIntArrayToStringArray(values)

	return json.Marshal(s)
}

// AtomicQueryMTPV2PubSignals public signals
type AtomicQueryMTPV2PubSignals struct {
	BaseConfig
	RequestID              *big.Int         `json:"requestID"`
	UserID                 *core.ID         `json:"userID"`
	IssuerID               *core.ID         `json:"issuerID"`
	IssuerClaimIdenState   *merkletree.Hash `json:"issuerClaimIdenState"`
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
}

// PubSignalsUnmarshal unmarshal credentialAtomicQueryMTP.circom public signals array to AtomicQueryMTPPubSignals
func (ao *AtomicQueryMTPV2PubSignals) PubSignalsUnmarshal(data []byte) error {

	// expected order:
	// merklized
	// userID
	// requestID
	// issuerID
	// issuerClaimIdenState
	// isRevocationChecked
	// issuerClaimNonRevState
	// timestamp
	// claimSchema
	// claimPathNotExists
	// claimPathKey
	// slotIndex
	// operator
	// value

	// 13 is a number of fields in AtomicQueryMTPV2PubSignals before values, values is last element in the proof and
	// it is length could be different base on the circuit configuration. The length could be modified by set value
	// in ValueArraySize
	const fieldLength = 13

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

	// - requestID
	var ok bool
	if ao.RequestID, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid requestID value: '%s'", sVals[fieldIdx])
	}
	fieldIdx++

	// - issuerID
	if ao.IssuerID, err = idFromIntStr(sVals[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++

	// - issuerClaimIdenState
	if ao.IssuerClaimIdenState, err = merkletree.NewHashFromString(sVals[fieldIdx]); err != nil {
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
		return fmt.Errorf("invalid schema value: '%s'", sVals[fieldIdx])
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

	return nil
}

// GetObjMap returns struct field as a map
func (ao AtomicQueryMTPV2PubSignals) GetObjMap() map[string]interface{} {
	return toMap(ao)
}
