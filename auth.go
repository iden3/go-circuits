package circuits

import (
	"encoding/json"
	"fmt"
	"math/big"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/pkg/errors"
)

// AuthInputs type represent auth.circom private inputs
type AuthInputs struct {
	BaseConfig

	ID *core.ID

	AuthClaim ClaimWithMTPProof

	Signature *babyjub.Signature
	Challenge *big.Int
}

// authCircuitInputs type reflect auth.circom private inputs required by prover
type authCircuitInputs struct {
	UserAuthClaim               *core.Claim      `json:"userAuthClaim"`
	UserAuthClaimMtp            []string         `json:"userAuthClaimMtp"`
	UserAuthClaimNonRevMtp      []string         `json:"userAuthClaimNonRevMtp"`
	UserAuthClaimNonRevMtpAuxHi *merkletree.Hash `json:"userAuthClaimNonRevMtpAuxHi"`
	UserAuthClaimNonRevMtpAuxHv *merkletree.Hash `json:"userAuthClaimNonRevMtpAuxHv"`
	UserAuthClaimNonRevMtpNoAux string           `json:"userAuthClaimNonRevMtpNoAux"`
	Challenge                   string           `json:"challenge"`
	ChallengeSignatureR8X       string           `json:"challengeSignatureR8x"`
	ChallengeSignatureR8Y       string           `json:"challengeSignatureR8y"`
	ChallengeSignatureS         string           `json:"challengeSignatureS"`
	UserClaimsTreeRoot          *merkletree.Hash `json:"userClaimsTreeRoot"`
	UserID                      string           `json:"userID"`
	UserRevTreeRoot             *merkletree.Hash `json:"userRevTreeRoot"`
	UserRootsTreeRoot           *merkletree.Hash `json:"userRootsTreeRoot"`
	UserState                   *merkletree.Hash `json:"userState"`
}

// InputsMarshal returns Circom private inputs for auth.circom
func (a AuthInputs) InputsMarshal() ([]byte, error) {

	if a.AuthClaim.IncProof.Proof == nil {
		return nil, errors.New(ErrorEmptyAuthClaimProof)
	}

	if a.AuthClaim.NonRevProof.Proof == nil {
		return nil, errors.New(ErrorEmptyAuthClaimNonRevProof)
	}

	if a.Signature == nil {
		return nil, errors.New(ErrorEmptyChallengeSignature)
	}

	s := authCircuitInputs{
		UserAuthClaim: a.AuthClaim.Claim,
		UserAuthClaimMtp: PrepareSiblingsStr(a.AuthClaim.IncProof.Proof.AllSiblings(),
			a.GetMTLevel()),
		UserAuthClaimNonRevMtp: PrepareSiblingsStr(a.AuthClaim.NonRevProof.Proof.AllSiblings(),
			a.GetMTLevel()),
		Challenge:             a.Challenge.String(),
		ChallengeSignatureR8X: a.Signature.R8.X.String(),
		ChallengeSignatureR8Y: a.Signature.R8.Y.String(),
		ChallengeSignatureS:   a.Signature.S.String(),
		UserClaimsTreeRoot:    a.AuthClaim.IncProof.TreeState.ClaimsRoot,
		UserID:                a.ID.BigInt().String(),
		UserRevTreeRoot:       a.AuthClaim.IncProof.TreeState.RevocationRoot,
		UserRootsTreeRoot:     a.AuthClaim.IncProof.TreeState.RootOfRoots,
		UserState:             a.AuthClaim.IncProof.TreeState.State,
	}

	nodeAuxAuth := GetNodeAuxValue(a.AuthClaim.NonRevProof.Proof)
	s.UserAuthClaimNonRevMtpAuxHi = nodeAuxAuth.key
	s.UserAuthClaimNonRevMtpAuxHv = nodeAuxAuth.value
	s.UserAuthClaimNonRevMtpNoAux = nodeAuxAuth.noAux

	return json.Marshal(s)
}

// AuthPubSignals auth.circom public signals
type AuthPubSignals struct {
	Challenge *big.Int         `json:"challenge"`
	UserState *merkletree.Hash `json:"userState"`
	UserID    *core.ID         `json:"userID"`
}

// PubSignalsUnmarshal unmarshal auth.circom public inputs to AuthPubSignals
func (a *AuthPubSignals) PubSignalsUnmarshal(data []byte) error {
	var sVals []string
	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	if len(sVals) != 3 {
		return fmt.Errorf("invalid number of Output values expected {%d} got {%d} ", 3, len(sVals))
	}

	var ok bool
	if a.Challenge, ok = big.NewInt(0).SetString(sVals[0], 10); !ok {
		return fmt.Errorf("invalid challenge value: '%s'", sVals[0])
	}

	if a.UserState, err = merkletree.NewHashFromString(sVals[1]); err != nil {
		return err
	}

	if a.UserID, err = idFromIntStr(sVals[2]); err != nil {
		return err
	}

	return nil
}

// GetObjMap returns AuthPubSignals as a map
func (a AuthPubSignals) GetObjMap() map[string]interface{} {
	return toMap(a)
}
