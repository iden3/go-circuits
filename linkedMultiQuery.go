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

const LinkedMultiQueryLength = 10

// LinkedMultiQueryInputs type represent linkedMultiQuery10.circom inputs
type LinkedMultiQueryInputs struct {
	BaseConfig
	LinkNonce *big.Int
	Claim     *core.Claim
	Query     []*Query
}

// linkedMultiQueryCircuitInputs type reflect linkedMultiQuery10.circom private inputs required by prover
type linkedMultiQueryCircuitInputs struct {
	LinkNonce            string             `json:"linkNonce"`
	IssuerClaim          *core.Claim        `json:"issuerClaim"`
	ClaimSchema          string             `json:"claimSchema"`
	ClaimPathMtp         [][]string         `json:"claimPathMtp"`
	ClaimPathMtpNoAux    []string           `json:"claimPathMtpNoAux"` // 1 if aux node is empty, 0 if non-empty or for inclusion proofs
	ClaimPathMtpAuxHi    []*merkletree.Hash `json:"claimPathMtpAuxHi"` // 0 for inclusion proof
	ClaimPathMtpAuxHv    []*merkletree.Hash `json:"claimPathMtpAuxHv"` // 0 for inclusion proof
	ClaimPathKey         []string           `json:"claimPathKey"`      // hash of path in merklized json-ld document
	ClaimPathValue       []string           `json:"claimPathValue"`    // value in this path in merklized json-ld document
	SlotIndex            []int              `json:"slotIndex"`
	Operator             []int              `json:"operator"`
	Value                [][]string         `json:"value"`
	ActualValueArraySize []int              `json:"valueArraySize"`
}

func (l LinkedMultiQueryInputs) Validate() error {
	if l.LinkNonce == nil {
		return errors.New(ErrorEmptyLinkNonce)
	}

	if l.Claim == nil {
		return errors.New(ErrorEmptyClaim)
	}

	if len(l.Query) == 0 {
		return errors.New(ErrorEmptyQueries)
	}

	if len(l.Query) > LinkedMultiQueryLength {
		return errors.New(ErrorTooManyQueries)
	}

	for _, q := range l.Query {
		if q == nil {
			continue
		}
		if err := q.ValidateValueArraySize(l.GetValueArrSize()); err != nil {
			return err
		}
	}

	return nil
}

// InputsMarshal returns Circom private inputs for linkedMultiQuery10.circom
func (l LinkedMultiQueryInputs) InputsMarshal() ([]byte, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}

	s := linkedMultiQueryCircuitInputs{}
	s.LinkNonce = l.LinkNonce.String()
	s.IssuerClaim = l.Claim
	s.ClaimSchema = l.Claim.GetSchemaHash().BigInt().String()

	s.ClaimPathMtp = make([][]string, LinkedMultiQueryLength)
	s.ClaimPathMtpNoAux = make([]string, LinkedMultiQueryLength)
	s.ClaimPathMtpAuxHi = make([]*merkletree.Hash, LinkedMultiQueryLength)
	s.ClaimPathMtpAuxHv = make([]*merkletree.Hash, LinkedMultiQueryLength)
	s.ClaimPathKey = make([]string, LinkedMultiQueryLength)
	s.ClaimPathValue = make([]string, LinkedMultiQueryLength)
	s.SlotIndex = make([]int, LinkedMultiQueryLength)
	s.Operator = make([]int, LinkedMultiQueryLength)
	s.Value = make([][]string, LinkedMultiQueryLength)
	s.ActualValueArraySize = make([]int, LinkedMultiQueryLength)

	for i := 0; i < LinkedMultiQueryLength; i++ {
		if i >= len(l.Query) || l.Query[i] == nil {
			s.ClaimPathMtp[i] = PrepareSiblingsStr([]*merkletree.Hash{}, l.GetMTLevelsClaim())

			s.ClaimPathMtpNoAux[i] = "0"
			s.ClaimPathMtpAuxHi[i] = &merkletree.HashZero
			s.ClaimPathMtpAuxHv[i] = &merkletree.HashZero

			s.ClaimPathKey[i] = "0"
			s.ClaimPathValue[i] = "0"

			s.SlotIndex[i] = 0
			s.Operator[i] = 0

			values, err := PrepareCircuitArrayValues(make([]*big.Int, 0), l.GetValueArrSize())
			if err != nil {
				return nil, err
			}
			s.Value[i] = bigIntArrayToStringArray(values)
			s.ActualValueArraySize[i] = 0
			continue
		}

		valueProof := l.Query[i].ValueProof
		if valueProof == nil {
			valueProof = &ValueProof{}
			valueProof.Path = big.NewInt(0)
			valueProof.Value = big.NewInt(0)
			valueProof.MTP = &merkletree.Proof{}
		}

		s.ClaimPathMtp[i] = PrepareSiblingsStr(valueProof.MTP.AllSiblings(),
			l.GetMTLevelsClaim())

		nodAuxJSONLD := GetNodeAuxValue(valueProof.MTP)
		s.ClaimPathMtpNoAux[i] = nodAuxJSONLD.noAux
		s.ClaimPathMtpAuxHi[i] = nodAuxJSONLD.key
		s.ClaimPathMtpAuxHv[i] = nodAuxJSONLD.value

		s.ClaimPathKey[i] = valueProof.Path.String()
		s.ClaimPathValue[i] = valueProof.Value.String()

		s.SlotIndex[i] = l.Query[i].SlotIndex
		s.Operator[i] = l.Query[i].Operator
		s.ActualValueArraySize[i] = len(l.Query[i].Values)
		values, err := PrepareCircuitArrayValues(l.Query[i].Values, l.GetValueArrSize())
		if err != nil {
			return nil, err
		}
		s.Value[i] = bigIntArrayToStringArray(values)
	}

	return json.Marshal(s)
}

// LinkedMultiQueryPubSignals linkedMultiQuery10.circom public signals
type LinkedMultiQueryPubSignals struct {
	LinkID           *big.Int   `json:"linkID"`
	Merklized        int        `json:"merklized"`
	OperatorOutput   []*big.Int `json:"operatorOutput"`
	CircuitQueryHash []*big.Int `json:"circuitQueryHash"`
}

// PubSignalsUnmarshal unmarshal linkedMultiQuery10.circom public inputs to LinkedMultiQueryPubSignals
func (lo *LinkedMultiQueryPubSignals) PubSignalsUnmarshal(data []byte) error {
	// expected order:
	// linkID
	// merklized
	// operatorOutput
	// circuitQueryHash

	outputsLength := LinkedMultiQueryLength*2 + 2
	var sVals []string
	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	if len(sVals) != outputsLength {
		return fmt.Errorf("invalid number of Output values expected {%d} go {%d} ", outputsLength, len(sVals))
	}

	var ok bool
	fieldIdx := 0

	// - linkID
	if lo.LinkID, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid link ID value: '%s'", sVals[fieldIdx])
	}
	fieldIdx++

	// -- merklized
	if lo.Merklized, err = strconv.Atoi(sVals[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++

	// -- operatorOutput
	lo.OperatorOutput = make([]*big.Int, LinkedMultiQueryLength)
	for i := 0; i < LinkedMultiQueryLength; i++ {
		if lo.OperatorOutput[i], ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
			return fmt.Errorf("invalid operator output value: '%s'", sVals[fieldIdx])
		}
		fieldIdx++
	}
	// -- circuitQueryHash
	lo.CircuitQueryHash = make([]*big.Int, LinkedMultiQueryLength)
	for i := 0; i < LinkedMultiQueryLength; i++ {
		if lo.CircuitQueryHash[i], ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
			return fmt.Errorf("invalid query hash value: '%s'", sVals[fieldIdx])
		}
		fieldIdx++
	}

	return nil
}

// GetObjMap returns LinkedMultiQueryPubSignals as a map
func (l LinkedMultiQueryPubSignals) GetObjMap() map[string]interface{} {
	return toMap(l)
}
