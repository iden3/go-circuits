package circuits

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/fatih/structs"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql"
)

// AuthInputs ZK inputs
type AuthInputs struct {
	BaseConfig

	ID *core.ID

	AuthClaim Claim

	Signature *babyjub.Signature
	Challenge *big.Int

	InputMarshaller
}

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

func (a AuthInputs) CircuitInputMarshal() ([]byte, error) {

	s := authCircuitInputs{
		UserAuthClaim: a.AuthClaim.Claim,
		UserAuthClaimMtp: PrepareSiblingsStr(a.AuthClaim.Proof.AllSiblings(),
			a.GetMTLevel()),
		UserAuthClaimNonRevMtp: PrepareSiblingsStr(a.AuthClaim.NonRevProof.Proof.AllSiblings(),
			a.GetMTLevel()),
		Challenge:             a.Challenge.String(),
		ChallengeSignatureR8X: a.Signature.R8.X.String(),
		ChallengeSignatureR8Y: a.Signature.R8.Y.String(),
		ChallengeSignatureS:   a.Signature.S.String(),
		UserClaimsTreeRoot:    a.AuthClaim.TreeState.ClaimsRoot,
		UserID:                a.ID.BigInt().String(),
		UserRevTreeRoot:       a.AuthClaim.TreeState.RevocationRoot,
		UserRootsTreeRoot:     a.AuthClaim.TreeState.RootOfRoots,
		UserState:             a.AuthClaim.TreeState.State,
	}

	nodeAuxAuth := getNodeAuxValue(a.AuthClaim.Proof.NodeAux)
	s.UserAuthClaimNonRevMtpAuxHi = nodeAuxAuth.key
	s.UserAuthClaimNonRevMtpAuxHv = nodeAuxAuth.value
	s.UserAuthClaimNonRevMtpNoAux = nodeAuxAuth.noAux

	return json.Marshal(s)
}

type AuthOutputs struct {
	Challenge *big.Int         `json:"challenge"`
	UserState *merkletree.Hash `json:"userState"`
	UserID    *core.ID         `json:"userID"`
}

func (a *AuthOutputs) CircuitOutputUnmarshal(data []byte) error {
	var sVals []string
	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	if len(sVals) != 3 {
		return fmt.Errorf("invalid number of output values expected {%d} got {%d} ", 3, len(sVals))
	}

	var ok bool
	if a.Challenge, ok = big.NewInt(0).SetString(sVals[0], 10); !ok {
		return fmt.Errorf("invalid challenge value: '%s'", sVals[0])
	}

	if a.UserState, err = merkletree.NewHashFromString(sVals[1]); err != nil {
		return err
	}

	if a.UserID, err = IDFromStr(sVals[2]); err != nil {
		return err
	}

	return nil
}

func (a AuthOutputs) GetJSONObjMap() map[string]interface{} {
	return structs.Map(a)
}
