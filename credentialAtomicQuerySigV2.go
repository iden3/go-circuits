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

// AtomicQuerySigInputs ZK private inputs for credentialAtomicQuerySig.circom
type AtomicQuerySigV2Inputs struct {
	BaseConfig

	RequestID *big.Int

	// auth
	ID                       *core.ID
	ProfileNonce             *big.Int
	ClaimSubjectProfileNonce *big.Int

	Claim                    ClaimWithSigProof // issuerClaim
	SkipClaimRevocationCheck bool

	// query
	Query Query

	CurrentTimeStamp int64
}

// atomicQuerySigCircuitInputs type represents credentialAtomicQuerySig.circom private inputs required by prover
type atomicQuerySigV2CircuitInputs struct {
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
}

func (a AtomicQuerySigV2Inputs) Validate() error {

	if a.RequestID == nil {
		return errors.New(ErrorEmptyRequestID)
	}

	if a.Claim.NonRevProof.Proof == nil {
		return errors.New(ErrorEmptyClaimNonRevProof)
	}

	if a.Claim.SignatureProof.IssuerAuthIncProof.Proof == nil {
		return errors.New(ErrorEmptyIssuerAuthClaimProof)
	}

	if a.Claim.SignatureProof.IssuerAuthNonRevProof.Proof == nil {
		return errors.New(ErrorEmptyIssuerAuthClaimNonRevProof)
	}

	if a.Claim.SignatureProof.Signature == nil {
		return errors.New(ErrorEmptyClaimSignature)
	}

	if a.Query.Values == nil {
		return errors.New(ErrorEmptyQueryValue)
	}

	profileID, err := core.ProfileID(*a.ID, a.ClaimSubjectProfileNonce)
	if err != nil {
		return errors.Errorf("failed to generate profile ID: %v", err)
	}
	credentialSubjectID, err := a.Claim.Claim.GetID()
	if err != nil {
		return errors.Errorf("failed to get credential subject ID: %v", err)
	}
	if profileID.BigInt().Cmp(credentialSubjectID.BigInt()) != 0 {
		return errors.New(ErrorUserProfileMismatch)
	}

	return nil
}

// InputsMarshal returns Circom private inputs for credentialAtomicQuerySig.circom
func (a AtomicQuerySigV2Inputs) InputsMarshal() ([]byte, error) {

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

	s := atomicQuerySigV2CircuitInputs{
		RequestID:                       a.RequestID.String(),
		UserGenesisID:                   a.ID.BigInt().String(),
		ProfileNonce:                    a.ProfileNonce.String(),
		ClaimSubjectProfileNonce:        a.ClaimSubjectProfileNonce.String(),
		IssuerID:                        a.Claim.IssuerID.BigInt().String(),
		IssuerClaim:                     a.Claim.Claim,
		IssuerClaimNonRevClaimsTreeRoot: a.Claim.NonRevProof.TreeState.ClaimsRoot.BigInt().String(),
		IssuerClaimNonRevRevTreeRoot:    a.Claim.NonRevProof.TreeState.RevocationRoot.BigInt().String(),
		IssuerClaimNonRevRootsTreeRoot:  a.Claim.NonRevProof.TreeState.RootOfRoots.BigInt().String(),
		IssuerClaimNonRevState:          a.Claim.NonRevProof.TreeState.State.BigInt().String(),
		IssuerClaimNonRevMtp: PrepareSiblingsStr(a.Claim.NonRevProof.Proof.AllSiblings(),
			a.GetMTLevel()),
		IssuerClaimSignatureR8X: a.Claim.SignatureProof.Signature.R8.X.String(),
		IssuerClaimSignatureR8Y: a.Claim.SignatureProof.Signature.R8.Y.String(),
		IssuerClaimSignatureS:   a.Claim.SignatureProof.Signature.S.String(),
		IssuerAuthClaim:         a.Claim.SignatureProof.IssuerAuthClaim,
		IssuerAuthClaimMtp: PrepareSiblingsStr(a.Claim.SignatureProof.IssuerAuthIncProof.Proof.AllSiblings(),
			a.GetMTLevel()),
		IssuerAuthClaimsTreeRoot: a.Claim.SignatureProof.IssuerAuthIncProof.TreeState.ClaimsRoot.
			BigInt().String(),
		IssuerAuthRevTreeRoot:   a.Claim.SignatureProof.IssuerAuthIncProof.TreeState.RevocationRoot.BigInt().String(),
		IssuerAuthRootsTreeRoot: a.Claim.SignatureProof.IssuerAuthIncProof.TreeState.RootOfRoots.BigInt().String(),

		IssuerAuthClaimNonRevMtp: PrepareSiblingsStr(a.Claim.SignatureProof.IssuerAuthNonRevProof.Proof.
			AllSiblings(), a.GetMTLevel()),

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

	nodeAuxNonRev := GetNodeAuxValue(a.Claim.NonRevProof.Proof)
	s.IssuerClaimNonRevMtpAuxHi = nodeAuxNonRev.key
	s.IssuerClaimNonRevMtpAuxHv = nodeAuxNonRev.value
	s.IssuerClaimNonRevMtpNoAux = nodeAuxNonRev.noAux

	nodeAuxIssuerAuthNonRev := GetNodeAuxValue(a.Claim.SignatureProof.IssuerAuthNonRevProof.Proof)
	s.IssuerAuthClaimNonRevMtpAuxHi = nodeAuxIssuerAuthNonRev.key
	s.IssuerAuthClaimNonRevMtpAuxHv = nodeAuxIssuerAuthNonRev.value
	s.IssuerAuthClaimNonRevMtpNoAux = nodeAuxIssuerAuthNonRev.noAux

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

	return json.Marshal(s)
}

func (a AtomicQuerySigV2Inputs) GetPublicStatesInfo() (StatesInfo, error) {
	if err := a.Validate(); err != nil {
		return StatesInfo{}, err
	}

	issuerID := a.Claim.IssuerID
	var issuerState merkletree.Hash
	if a.Claim.SignatureProof.IssuerAuthIncProof.TreeState.State == nil {
		return StatesInfo{}, errors.New(ErrorEmptyStateHash)
	}
	issuerState = *a.Claim.SignatureProof.IssuerAuthIncProof.TreeState.State

	if a.Claim.NonRevProof.TreeState.State == nil {
		return StatesInfo{}, errors.New(ErrorEmptyStateHash)
	}

	statesInfo := StatesInfo{
		States: []State{
			{
				ID:    *issuerID,
				State: issuerState,
			},
		},
		Gists: []Gist{},
	}

	nonRevProofState := *a.Claim.NonRevProof.TreeState.State
	if issuerState != nonRevProofState {
		statesInfo.States = append(statesInfo.States, State{
			ID:    *issuerID,
			State: nonRevProofState,
		})
	}

	return statesInfo, nil
}

// AtomicQuerySigV2PubSignals public inputs
type AtomicQuerySigV2PubSignals struct {
	BaseConfig
	RequestID              *big.Int         `json:"requestID"`
	UserID                 *core.ID         `json:"userID"`
	IssuerID               *core.ID         `json:"issuerID"`
	IssuerAuthState        *merkletree.Hash `json:"issuerAuthState"`
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

// PubSignalsUnmarshal unmarshal credentialAtomicQuerySig.circom public signals
func (ao *AtomicQuerySigV2PubSignals) PubSignalsUnmarshal(data []byte) error {
	// expected order:
	// merklized
	// userID
	// issuerAuthState
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

	// 12 is a number of fields in AtomicQuerySigV2PubSignals before values, values is last element in the proof and
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

	// - issuerAuthState
	if ao.IssuerAuthState, err = merkletree.NewHashFromString(sVals[fieldIdx]); err != nil {
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

	return nil
}

// GetObjMap returns struct field as a map
func (ao AtomicQuerySigV2PubSignals) GetObjMap() map[string]interface{} {
	return toMap(ao)
}

func (ao AtomicQuerySigV2PubSignals) GetStatesInfo() (StatesInfo, error) {
	if ao.IssuerID == nil {
		return StatesInfo{}, errors.New(ErrorEmptyID)
	}

	if ao.IssuerAuthState == nil || ao.IssuerClaimNonRevState == nil {
		return StatesInfo{}, errors.New(ErrorEmptyStateHash)
	}

	states := []State{
		{
			ID:    *ao.IssuerID,
			State: *ao.IssuerAuthState,
		},
	}
	if *ao.IssuerClaimNonRevState != *ao.IssuerAuthState {
		states = append(states, State{
			ID:    *ao.IssuerID,
			State: *ao.IssuerClaimNonRevState,
		})
	}

	return StatesInfo{States: states, Gists: []Gist{}}, nil
}
