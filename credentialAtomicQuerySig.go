package circuits

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"

	"github.com/fatih/structs"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql"
)

// AtomicQuerySigInputs ZK private inputs for credentialAtomicQuerySig.circom
type AtomicQuerySigInputs struct {
	BaseConfig

	// auth
	ID        *core.ID
	AuthClaim Claim
	Challenge *big.Int
	Signature *babyjub.Signature

	Claim // issuerClaim

	Query

	CurrentTimeStamp int64
	Schema           core.SchemaHash
}

// atomicQuerySigCircuitInputs type represents credentialAtomicQuerySig.circom private inputs required by prover
type atomicQuerySigCircuitInputs struct {
	UserAuthClaim               *core.Claim      `json:"userAuthClaim"`
	UserAuthClaimMtp            []string         `json:"userAuthClaimMtp"`
	UserAuthClaimNonRevMtp      []string         `json:"userAuthClaimNonRevMtp"`
	UserAuthClaimNonRevMtpAuxHi *merkletree.Hash `json:"userAuthClaimNonRevMtpAuxHi"`
	UserAuthClaimNonRevMtpAuxHv *merkletree.Hash `json:"userAuthClaimNonRevMtpAuxHv"`
	UserAuthClaimNonRevMtpNoAux string           `json:"userAuthClaimNonRevMtpNoAux"`
	UserClaimsTreeRoot          *merkletree.Hash `json:"userClaimsTreeRoot"`
	UserState                   *merkletree.Hash `json:"userState"`
	UserRevTreeRoot             *merkletree.Hash `json:"userRevTreeRoot"`
	UserRootsTreeRoot           *merkletree.Hash `json:"userRootsTreeRoot"`
	UserID                      string           `json:"userID"`

	Challenge             string `json:"challenge"`
	ChallengeSignatureR8X string `json:"challengeSignatureR8x"`
	ChallengeSignatureR8Y string `json:"challengeSignatureR8y"`
	ChallengeSignatureS   string `json:"challengeSignatureS"`

	IssuerClaim                     *core.Claim      `json:"issuerClaim"`
	IssuerClaimNonRevClaimsTreeRoot *merkletree.Hash `json:"issuerClaimNonRevClaimsTreeRoot"`
	IssuerClaimNonRevRevTreeRoot    *merkletree.Hash `json:"issuerClaimNonRevRevTreeRoot"`
	IssuerClaimNonRevRootsTreeRoot  *merkletree.Hash `json:"issuerClaimNonRevRootsTreeRoot"`
	IssuerClaimNonRevState          *merkletree.Hash `json:"issuerClaimNonRevState"`
	IssuerClaimNonRevMtp            []string         `json:"issuerClaimNonRevMtp"`
	IssuerClaimNonRevMtpAuxHi       *merkletree.Hash `json:"issuerClaimNonRevMtpAuxHi"`
	IssuerClaimNonRevMtpAuxHv       *merkletree.Hash `json:"issuerClaimNonRevMtpAuxHv"`
	IssuerClaimNonRevMtpNoAux       string           `json:"issuerClaimNonRevMtpNoAux"`
	ClaimSchema                     string           `json:"claimSchema"`
	IssuerID                        string           `json:"issuerID"`
	Operator                        int              `json:"operator"`
	SlotIndex                       int              `json:"slotIndex"`
	Timestamp                       int64            `json:"timestamp,string"`
	Value                           []string         `json:"value"`

	IssuerClaimSignatureR8X string           `json:"issuerClaimSignatureR8x"`
	IssuerClaimSignatureR8Y string           `json:"issuerClaimSignatureR8y"`
	IssuerClaimSignatureS   string           `json:"issuerClaimSignatureS"`
	IssuerAuthClaimMtp      []string         `json:"issuerAuthClaimMtp"`
	IssuerAuthHi            string           `json:"issuerAuthHi"`
	IssuerAuthHv            string           `json:"issuerAuthHv"`
	IssuerClaimsTreeRoot    *merkletree.Hash `json:"issuerClaimsTreeRoot"`
	IssuerState             *merkletree.Hash `json:"issuerState"`
	IssuerPubKeyX           string           `json:"issuerPubKeyX"`
	IssuerPubKeyY           string           `json:"issuerPubKeyY"`
	IssuerRevTreeRoot       *merkletree.Hash `json:"issuerRevTreeRoot"`
	IssuerRootsTreeRoot     *merkletree.Hash `json:"issuerRootsTreeRoot"`
}

// CircuitInputMarshal returns Circom private inputs for credentialAtomicQuerySig.circom
func (a AtomicQuerySigInputs) InputsMarshal() ([]byte, error) {

	s := atomicQuerySigCircuitInputs{
		UserAuthClaim: a.AuthClaim.Claim,
		UserAuthClaimMtp: PrepareSiblingsStr(a.AuthClaim.Proof.AllSiblings(),
			a.GetMTLevel()),
		UserAuthClaimNonRevMtp: PrepareSiblingsStr(a.AuthClaim.NonRevProof.Proof.AllSiblings(),
			a.GetMTLevel()),
		Challenge:                       a.Challenge.String(),
		ChallengeSignatureR8X:           a.Signature.R8.X.String(),
		ChallengeSignatureR8Y:           a.Signature.R8.Y.String(),
		ChallengeSignatureS:             a.Signature.S.String(),
		IssuerClaim:                     a.Claim.Claim,
		IssuerClaimNonRevClaimsTreeRoot: a.Claim.NonRevProof.TreeState.ClaimsRoot,
		IssuerClaimNonRevRevTreeRoot:    a.Claim.NonRevProof.TreeState.RevocationRoot,
		IssuerClaimNonRevRootsTreeRoot:  a.Claim.NonRevProof.TreeState.RootOfRoots,
		IssuerClaimNonRevState:          a.Claim.NonRevProof.TreeState.State,
		IssuerClaimNonRevMtp: PrepareSiblingsStr(a.Claim.NonRevProof.Proof.AllSiblings(),
			a.GetMTLevel()),
		ClaimSchema:             new(big.Int).SetBytes(a.Schema[:]).String(),
		UserClaimsTreeRoot:      a.AuthClaim.TreeState.ClaimsRoot,
		UserState:               a.AuthClaim.TreeState.State,
		UserRevTreeRoot:         a.AuthClaim.TreeState.RevocationRoot,
		UserRootsTreeRoot:       a.AuthClaim.TreeState.RootOfRoots,
		UserID:                  a.ID.BigInt().String(),
		IssuerID:                a.IssuerID.BigInt().String(),
		Operator:                a.Operator,
		SlotIndex:               a.SlotIndex,
		Timestamp:               a.CurrentTimeStamp,
		IssuerClaimSignatureR8X: a.SignatureProof.Signature.R8.X.String(),
		IssuerClaimSignatureR8Y: a.SignatureProof.Signature.R8.Y.String(),
		IssuerClaimSignatureS:   a.SignatureProof.Signature.S.String(),

		IssuerAuthClaimMtp: bigIntArrayToStringArray(
			PrepareSiblings(a.SignatureProof.AuthClaimIssuerMTP.AllSiblings(), a.GetMTLevel())),
		IssuerAuthHi:         a.SignatureProof.HIndex.BigInt().String(),
		IssuerAuthHv:         a.SignatureProof.HValue.BigInt().String(),
		IssuerClaimsTreeRoot: a.SignatureProof.IssuerTreeState.ClaimsRoot,
		IssuerState:          a.SignatureProof.IssuerTreeState.State,
		IssuerPubKeyX:        a.SignatureProof.IssuerPublicKey.X.String(),
		IssuerPubKeyY:        a.SignatureProof.IssuerPublicKey.Y.String(),
		IssuerRevTreeRoot:    a.SignatureProof.IssuerTreeState.RevocationRoot,
		IssuerRootsTreeRoot:  a.SignatureProof.IssuerTreeState.RootOfRoots,
	}

	values, err := PrepareCircuitArrayValues(a.Values, a.GetValueArrSize())
	if err != nil {
		return nil, err
	}
	s.Value = bigIntArrayToStringArray(values)

	nodeAuxAuth := getNodeAuxValue(a.Claim.NonRevProof.Proof.NodeAux)
	s.UserAuthClaimNonRevMtpAuxHi = nodeAuxAuth.key
	s.UserAuthClaimNonRevMtpAuxHv = nodeAuxAuth.value
	s.UserAuthClaimNonRevMtpNoAux = nodeAuxAuth.noAux

	nodeAux := getNodeAuxValue(a.Claim.NonRevProof.Proof.NodeAux)
	s.IssuerClaimNonRevMtpAuxHi = nodeAux.key
	s.IssuerClaimNonRevMtpAuxHv = nodeAux.value
	s.IssuerClaimNonRevMtpNoAux = nodeAux.noAux

	return json.Marshal(s)
}

// AtomicQuerySigPubSignals public inputs
type AtomicQuerySigPubSignals struct {
	UserID      *core.ID         `json:"userID"`
	UserState   *merkletree.Hash `json:"userState"`
	Challenge   *big.Int         `json:"challenge"`
	ClaimSchema core.SchemaHash  `json:"claimSchema"`
	IssuerID    *core.ID         `json:"issuerID"`
	IssuerState *merkletree.Hash `json:"issuerState"`
	SlotIndex   int              `json:"slotIndex"`
	Values      []*big.Int       `json:"values"`
	Operator    int              `json:"operator"`
	Timestamp   int64            `json:"timestamp"`
}

// PubSignalsUnmarshal unmarshal credentialAtomicQuerySig.circom public signals
func (ao *AtomicQuerySigPubSignals) PubSignalsUnmarshal(data []byte) error {
	var sVals []string
	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	if len(sVals) != 24 {
		return fmt.Errorf("invalid number of Output values expected {%d} go {%d} ", 24, len(sVals))
	}

	if ao.UserID, err = idFromIntStr(sVals[0]); err != nil {
		return err
	}

	if ao.UserState, err = merkletree.NewHashFromString(sVals[1]); err != nil {
		return err
	}

	var ok bool
	if ao.Challenge, ok = big.NewInt(0).SetString(sVals[2], 10); !ok {
		return fmt.Errorf("invalid challenge value: '%s'", sVals[0])
	}

	if ao.ClaimSchema, err = core.NewSchemaHashFromHex(sVals[3]); err != nil {
		return err
	}

	if ao.IssuerID, err = idFromIntStr(sVals[4]); err != nil {
		return err
	}

	if ao.IssuerState, err = merkletree.NewHashFromString(sVals[5]); err != nil {
		return err
	}

	if ao.SlotIndex, err = strconv.Atoi(sVals[6]); err != nil {
		return err
	}

	// 22 doesn't include in final slice.
	for i, v := range sVals[7:22] {
		bi, ok := big.NewInt(0).SetString(v, 10)
		if !ok {
			return fmt.Errorf("invalid value in index: %d", i)
		}
		ao.Values = append(ao.Values, bi)
	}

	if ao.Operator, err = strconv.Atoi(sVals[22]); err != nil {
		return err
	}

	if ao.Timestamp, err = strconv.ParseInt(sVals[23], 10, 64); err != nil {
		return err
	}

	return nil
}

// GetObjMap returns struct field as a map
func (ao AtomicQuerySigPubSignals) GetObjMap() map[string]interface{} {
	return structs.Map(ao)
}
