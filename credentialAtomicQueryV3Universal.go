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

// AtomicQueryV3UniversalPubSignals public inputs
type AtomicQueryV3UniversalPubSignals struct {
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
	IsRevocationChecked    int              `json:"isRevocationChecked"` // 0 revocation not check, // 1 for check revocation
	ProofType              int              `json:"proofType"`
	LinkID                 *big.Int         `json:"linkID"`
	Nullifier              *big.Int         `json:"nullifier"`
	OperatorOutput         *big.Int         `json:"operatorOutput"`
	VerifierID             *core.ID         `json:"verifierID"`
	NullifierSessionID     *big.Int         `json:"nullifierSessionID"`
	ActualValueArraySize   int              `json:"valueArraySize"`
	CircuitQueryHash       *big.Int         `json:"circuitQueryHash"`
}

// PubSignalsUnmarshal unmarshal credentialAtomicQueryV3Universal.circom public signals
func (ao *AtomicQueryV3UniversalPubSignals) PubSignalsUnmarshal(data []byte) error {
	// expected order:
	// userID
	// circuitQueryHash
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
	// claimPathKey
	// slotIndex
	// operator
	// value
	// valueArraySize
	// verifierID
	// nullifierSessionID

	// 19 is a number of fields in AtomicQueryV3UniversalPubSignals, values length could be
	// different base on the circuit configuration. The length could be modified by set value
	// in ValueArraySize
	const fieldLength = 19

	var sVals []string
	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	if len(sVals) != fieldLength+ao.GetValueArrSize() {
		return fmt.Errorf("invalid number of Output values expected {%d} got {%d} ", fieldLength+ao.GetValueArrSize(), len(sVals))
	}

	fieldIdx := 0
	
	//  - userID
	if ao.UserID, err = idFromIntStr(sVals[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++
	
	var ok bool
	// - circuitQueryHash
	if ao.CircuitQueryHash, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid circuit query hash value: '%s'", sVals[fieldIdx])
	}
	fieldIdx++

	// - issuerState
	if ao.IssuerState, err = merkletree.NewHashFromString(sVals[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++

	// - linkID
	if ao.LinkID, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid link ID value: '%s'", sVals[fieldIdx])
	}
	fieldIdx++

	// - nullifier
	if ao.Nullifier, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid nullifier value: '%s'", sVals[fieldIdx])
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
		return fmt.Errorf("invalid schema value: '%s'", sVals[fieldIdx])
	}
	ao.ClaimSchema = core.NewSchemaHashFromInt(schemaInt)
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

	// - valueArraySize
	if ao.ActualValueArraySize, err = strconv.Atoi(sVals[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++

	//  - VerifierID
	if sVals[fieldIdx] != "0" {
		if ao.VerifierID, err = idFromIntStr(sVals[fieldIdx]); err != nil {
			return err
		}
	}
	fieldIdx++

	//  - NullifierSessionID
	if ao.NullifierSessionID, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid verifier session ID: %s", sVals[fieldIdx])
	}

	return nil
}

// GetObjMap returns struct field as a map
func (ao AtomicQueryV3UniversalPubSignals) GetObjMap() map[string]interface{} {
	return toMap(ao)
}

func (ao AtomicQueryV3UniversalPubSignals) GetStatesInfo() (StatesInfo, error) {
	if ao.IssuerID == nil {
		return StatesInfo{}, errors.New(ErrorEmptyID)
	}

	if ao.IssuerState == nil || ao.IssuerClaimNonRevState == nil {
		return StatesInfo{}, errors.New(ErrorEmptyStateHash)
	}

	states := []State{
		{
			ID:    *ao.IssuerID,
			State: *ao.IssuerState,
		},
	}
	if *ao.IssuerClaimNonRevState != *ao.IssuerState {
		states = append(states, State{
			ID:    *ao.IssuerID,
			State: *ao.IssuerClaimNonRevState,
		})
	}

	return StatesInfo{States: states, Gists: []Gist{}}, nil
}
