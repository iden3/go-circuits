package circuits

import (
	"encoding/json"
	"fmt"

	"github.com/fatih/structs"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql"
)

// StateTransitionInputs ZK private inputs for stateTransition.circom
type StateTransitionInputs struct {
	BaseConfig

	ID *core.ID

	OldTreeState TreeState
	NewState     *merkletree.Hash

	AuthClaim                   Claim
	AuthClaimNonRevocationProof *merkletree.Proof
	Signature                   *babyjub.Signature
}

// stateTransitionInputsInternal type represents stateTransition.circom private inputs required by prover
type stateTransitionInputsInternal struct {
	AuthClaim               core.Claim       `json:"authClaim"`
	AuthClaimMtp            []string         `json:"authClaimMtp"`
	AuthClaimNonRevMtp      []string         `json:"authClaimNonRevMtp"`
	AuthClaimNonRevMtpAuxHi *merkletree.Hash `json:"authClaimNonRevMtpAuxHi"`
	AuthClaimNonRevMtpAuxHv *merkletree.Hash `json:"authClaimNonRevMtpAuxHv"`
	AuthClaimNonRevMtpNoAux string           `json:"authClaimNonRevMtpNoAux"`
	UserID                  string           `json:"userID"`
	NewIdState              *merkletree.Hash `json:"newUserState"`
	OldIdState              *merkletree.Hash `json:"oldUserState"`
	ClaimsTreeRoot          *merkletree.Hash `json:"claimsTreeRoot"`
	RevTreeRoot             *merkletree.Hash `json:"revTreeRoot"`
	RootsTreeRoot           *merkletree.Hash `json:"rootsTreeRoot"`
	SignatureR8X            string           `json:"signatureR8x"`
	SignatureR8Y            string           `json:"signatureR8y"`
	SignatureS              string           `json:"signatureS"`
}

// CircuitInputMarshal returns Circom private inputs for stateTransition.circom
func (c StateTransitionInputs) CircuitInputMarshal() ([]byte, error) {

	s := stateTransitionInputsInternal{
		AuthClaim:          *c.AuthClaim.Claim,
		AuthClaimMtp:       PrepareSiblingsStr(c.AuthClaim.Proof.AllSiblings(), c.GetMTLevel()),
		AuthClaimNonRevMtp: PrepareSiblingsStr(c.AuthClaimNonRevocationProof.AllSiblings(), c.GetMTLevel()),
		UserID:             c.ID.BigInt().String(),
		NewIdState:         c.NewState,
		ClaimsTreeRoot:     c.OldTreeState.ClaimsRoot,
		OldIdState:         c.OldTreeState.State,
		RevTreeRoot:        c.OldTreeState.RevocationRoot,
		RootsTreeRoot:      c.OldTreeState.RootOfRoots,
		SignatureR8X:       c.Signature.R8.X.String(),
		SignatureR8Y:       c.Signature.R8.Y.String(),
		SignatureS:         c.Signature.S.String(),
	}

	if c.AuthClaimNonRevocationProof.NodeAux == nil {
		s.AuthClaimNonRevMtpAuxHi = &merkletree.HashZero
		s.AuthClaimNonRevMtpAuxHv = &merkletree.HashZero
		s.AuthClaimNonRevMtpNoAux = "1"
	} else {
		s.AuthClaimNonRevMtpAuxHi = c.AuthClaimNonRevocationProof.NodeAux.Key
		s.AuthClaimNonRevMtpAuxHv = c.AuthClaimNonRevocationProof.NodeAux.Value
		s.AuthClaimNonRevMtpNoAux = "0"
	}

	return json.Marshal(s)
}

// StateTransitionPubSignals stateTransition.circom public inputs
type StateTransitionPubSignals struct {
	UserID       *core.ID         `json:"userID"`
	OldUserState *merkletree.Hash `json:"oldUserState"`
	NewUserState *merkletree.Hash `json:"newUserState"`
}

// PubSignalsUnmarshal unmarshal stateTransition.circom public signals
func (s *StateTransitionPubSignals) PubSignalsUnmarshal(data []byte) error {
	var sVals []string
	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	if len(sVals) != 3 {
		return fmt.Errorf("invalid number of Output values expected {%d} got {%d} ", 3, len(sVals))
	}

	if s.UserID, err = idFromIntStr(sVals[0]); err != nil {
		return err
	}
	if s.OldUserState, err = merkletree.NewHashFromString(sVals[1]); err != nil {
		return err
	}
	if s.NewUserState, err = merkletree.NewHashFromString(sVals[2]); err != nil {
		return err
	}
	return nil
}

// GetJSONObjMap returns struct field as a map
func (s StateTransitionPubSignals) GetJSONObjMap() map[string]interface{} {
	return structs.Map(s)
}
