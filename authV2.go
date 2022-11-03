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

// AuthV2Inputs type represent authV2.circom inputs
type AuthV2Inputs struct {
	BaseConfig

	ID    *core.ID
	Nonce *big.Int

	AuthClaim ClaimV2

	Signature *babyjub.Signature
	Challenge *big.Int
}

// authCircuitInputs type reflect auth.circom private inputs required by prover
type authV2CircuitInputs struct {
	// ID
	UserID string `json:"userGenesisID"`
	Nonce  string `json:"nonce"`

	// AuthClaim proof of inclusion
	UserAuthClaim    *core.Claim `json:"userAuthClaim"`
	UserAuthClaimMtp []string    `json:"userAuthClaimMtp"`

	// AuthClaim non revocation proof
	UserAuthClaimNonRevMtp      []string         `json:"userAuthClaimNonRevMtp"`
	UserAuthClaimNonRevMtpAuxHi *merkletree.Hash `json:"userAuthClaimNonRevMtpAuxHi"`
	UserAuthClaimNonRevMtpAuxHv *merkletree.Hash `json:"userAuthClaimNonRevMtpAuxHv"`
	UserAuthClaimNonRevMtpNoAux string           `json:"userAuthClaimNonRevMtpNoAux"`

	Challenge             string `json:"challenge"`
	ChallengeSignatureR8X string `json:"challengeSignatureR8x"`
	ChallengeSignatureR8Y string `json:"challengeSignatureR8y"`
	ChallengeSignatureS   string `json:"challengeSignatureS"`

	// User State
	UserClaimsTreeRoot *merkletree.Hash `json:"userClaimsTreeRoot"`
	UserRevTreeRoot    *merkletree.Hash `json:"userRevTreeRoot"`
	UserRootsTreeRoot  *merkletree.Hash `json:"userRootsTreeRoot"`
	UserState          *merkletree.Hash `json:"userState"`

	// Global on-cain state
	GlobalSmtRoot     *merkletree.Hash `json:"globalSmtRoot"`
	GlobalSmtMtp      []string         `json:"globalSmtMtp"`
	GlobalSmtMtpAuxHi *merkletree.Hash `json:"globalSmtMtpAuxHi"`
	GlobalSmtMtpAuxHv *merkletree.Hash `json:"globalSmtMtpAuxHv"`
	GlobalSmtMtpNoAux string           `json:"globalSmtMtpNoAux"`
}

// InputsMarshal returns Circom private inputs for auth.circom
func (a AuthV2Inputs) InputsMarshal() ([]byte, error) {

	if a.AuthClaim.MTProof.Proof == nil {
		return nil, errors.New(ErrorEmptyAuthClaimProof)
	}

	if a.AuthClaim.NonRevProof.Proof == nil {
		return nil, errors.New(ErrorEmptyAuthClaimNonRevProof)
	}

	if a.Signature == nil {
		return nil, errors.New(ErrorEmptyChallengeSignature)
	}

	s := authV2CircuitInputs{
		UserID:        a.ID.BigInt().String(),
		Nonce:         a.Nonce.String(),
		UserAuthClaim: a.AuthClaim.Claim,
		UserAuthClaimMtp: PrepareSiblingsStr(a.AuthClaim.MTProof.Proof.AllSiblings(),
			a.GetMTLevel()),
		UserAuthClaimNonRevMtp: PrepareSiblingsStr(a.AuthClaim.NonRevProof.Proof.AllSiblings(),
			a.GetMTLevel()),
		Challenge:             a.Challenge.String(),
		ChallengeSignatureR8X: a.Signature.R8.X.String(),
		ChallengeSignatureR8Y: a.Signature.R8.Y.String(),
		ChallengeSignatureS:   a.Signature.S.String(),
		UserClaimsTreeRoot:    a.AuthClaim.MTProof.TreeState.ClaimsRoot,
		UserRevTreeRoot:       a.AuthClaim.MTProof.TreeState.RevocationRoot,
		UserRootsTreeRoot:     a.AuthClaim.MTProof.TreeState.RootOfRoots,
		UserState:             a.AuthClaim.MTProof.TreeState.State,
		GlobalSmtRoot:         a.AuthClaim.GlobalTree.Root,
		GlobalSmtMtp:          PrepareSiblingsStr(a.AuthClaim.GlobalTree.Proof.AllSiblings(), a.GetMTLevelOnChain()),
		// TODO: change when pr with tree state will be merged
	}

	nodeAuxAuth := GetNodeAuxValue(a.AuthClaim.NonRevProof.Proof)
	s.UserAuthClaimNonRevMtpAuxHi = nodeAuxAuth.key
	s.UserAuthClaimNonRevMtpAuxHv = nodeAuxAuth.value
	s.UserAuthClaimNonRevMtpNoAux = nodeAuxAuth.noAux

	globalNodeAux := GetNodeAuxValue(a.AuthClaim.GlobalTree.Proof)
	s.GlobalSmtMtpAuxHi = globalNodeAux.key
	s.GlobalSmtMtpAuxHv = globalNodeAux.value
	s.GlobalSmtMtpNoAux = globalNodeAux.noAux

	return json.Marshal(s)
}

// AuthV2PubSignals auth.circom public signals
type AuthV2PubSignals struct {
	UserID     *core.ID         `json:"userID"`
	Challenge  *big.Int         `json:"challenge"`
	GlobalRoot *merkletree.Hash `json:"GlobalSmtRoot"`
}

// PubSignalsUnmarshal unmarshal auth.circom public inputs to AuthPubSignals
func (a *AuthV2PubSignals) PubSignalsUnmarshal(data []byte) error {
	var sVals []string
	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	if len(sVals) != 3 {
		return fmt.Errorf("invalid number of Output values expected {%d} got {%d} ", 3, len(sVals))
	}

	if a.UserID, err = idFromIntStr(sVals[0]); err != nil {
		return err
	}

	var ok bool
	if a.Challenge, ok = big.NewInt(0).SetString(sVals[1], 10); !ok {
		return fmt.Errorf("invalid challenge value: '%s'", sVals[0])
	}

	if a.GlobalRoot, err = merkletree.NewHashFromString(sVals[2]); err != nil {
		return err
	}

	return nil
}

// GetObjMap returns AuthPubSignals as a map
func (a AuthV2PubSignals) GetObjMap() map[string]interface{} {
	return toMap(a)
}
