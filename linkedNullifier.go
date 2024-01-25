package circuits

import (
	"encoding/json"
	"fmt"
	"math/big"

	core "github.com/iden3/go-iden3-core/v2"
)

// LinkedNullifierInputs type represent linkedNullifier.circom inputs
type LinkedNullifierInputs struct {
	LinkNonce                *big.Int
	IssuerClaim              *core.Claim
	ID                       *core.ID
	ClaimSubjectProfileNonce *big.Int
	VerifierID               *core.ID
	NullifierSessionID       *big.Int
}

// linkedNillifierCircuitInputs type reflect linkedNullifier.circom private inputs required by prover
type linkedNillifierCircuitInputs struct {
	LinkNonce                string      `json:"linkNonce"`
	IssuerClaim              *core.Claim `json:"issuerClaim"`
	UserGenesisID            string      `json:"userGenesisID"`
	ClaimSubjectProfileNonce string      `json:"claimSubjectProfileNonce"`
	ClaimSchema              string      `json:"claimSchema"`
	VerifierID               string      `json:"verifierID"`
	NullifierSessionID       string      `json:"nullifierSessionID"`
}

// InputsMarshal returns Circom private inputs for linkedNullifier.circom
func (l LinkedNullifierInputs) InputsMarshal() ([]byte, error) {
	s := linkedNillifierCircuitInputs{}

	s.LinkNonce = "0"
	if l.LinkNonce != nil {
		s.LinkNonce = l.LinkNonce.String()
	}

	s.IssuerClaim = l.IssuerClaim
	s.UserGenesisID = l.ID.BigInt().String()
	s.ClaimSubjectProfileNonce = l.ClaimSubjectProfileNonce.String()
	s.ClaimSchema = l.IssuerClaim.GetSchemaHash().BigInt().String()

	s.VerifierID = "0"
	if l.VerifierID != nil {
		s.VerifierID = l.VerifierID.BigInt().String()
	}

	s.NullifierSessionID = "0"
	if l.NullifierSessionID != nil {
		s.NullifierSessionID = l.NullifierSessionID.String()
	}

	return json.Marshal(s)
}

// LinkedNullifierPubSignals linkedNullifier.circom public signals
type LinkedNullifierPubSignals struct {
	Nullifier          *big.Int `json:"nullifier"`
	LinkID             *big.Int `json:"linkID"`
	VerifierID         *core.ID `json:"verifierID"`
	NullifierSessionID *big.Int `json:"nullifierSessionID"`
}

// PubSignalsUnmarshal unmarshal linkedNullifier.circom public inputs to LinkedNullifierPubSignals
func (lo *LinkedNullifierPubSignals) PubSignalsUnmarshal(data []byte) error {
	// expected order:
	// nullifier
	// linkID
	// verifierID
	// nullifierSessionID

	outputsLength := 4
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

	// - nullifier
	if lo.Nullifier, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid link ID value: '%s'", sVals[fieldIdx])
	}
	fieldIdx++

	// - linkID
	if lo.LinkID, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid link ID value: '%s'", sVals[fieldIdx])
	}
	fieldIdx++

	//  - verifierID
	if sVals[fieldIdx] != "0" {
		if lo.VerifierID, err = idFromIntStr(sVals[fieldIdx]); err != nil {
			return err
		}
	}
	fieldIdx++

	//  - nullifierSessionID
	if lo.NullifierSessionID, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid verifier session ID: %s", sVals[fieldIdx])
	}

	return nil
}

// GetObjMap returns LinkedNullifierPubSignals as a map
func (l LinkedNullifierPubSignals) GetObjMap() map[string]interface{} {
	return toMap(l)
}
