package circuits

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql"
	"github.com/pkg/errors"
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

	IssuerClaimSignatureR8X string      `json:"issuerClaimSignatureR8x"`
	IssuerClaimSignatureR8Y string      `json:"issuerClaimSignatureR8y"`
	IssuerClaimSignatureS   string      `json:"issuerClaimSignatureS"`
	IssuerAuthClaim         *core.Claim `json:"issuerAuthClaim"`
	IssuerAuthClaimMtp      []string    `json:"issuerAuthClaimMtp"`

	IssuerAuthClaimNonRevMtp      []string         `json:"issuerAuthClaimNonRevMtp"`
	IssuerAuthClaimNonRevMtpAuxHi *merkletree.Hash `json:"issuerAuthClaimNonRevMtpAuxHi"`
	IssuerAuthClaimNonRevMtpAuxHv *merkletree.Hash `json:"issuerAuthClaimNonRevMtpAuxHv"`
	IssuerAuthClaimNonRevMtpNoAux string           `json:"issuerAuthClaimNonRevMtpNoAux"`

	IssuerAuthClaimsTreeRoot *merkletree.Hash `json:"issuerAuthClaimsTreeRoot"`
	IssuerAuthRevTreeRoot    *merkletree.Hash `json:"issuerAuthRevTreeRoot"`
	IssuerAuthRootsTreeRoot  *merkletree.Hash `json:"issuerAuthRootsTreeRoot"`
}

// InputsMarshal returns Circom private inputs for credentialAtomicQuerySig.circom
func (a AtomicQuerySigInputs) InputsMarshal() ([]byte, error) {

	if a.AuthClaim.Proof == nil {
		return nil, errors.New(ErrorEmptyAuthClaimProof)
	}

	if a.AuthClaim.NonRevProof == nil || a.AuthClaim.NonRevProof.Proof == nil {
		return nil, errors.New(ErrorEmptyAuthClaimNonRevProof)
	}

	if a.Claim.NonRevProof == nil || a.Claim.NonRevProof.Proof == nil {
		return nil, errors.New(ErrorEmptyClaimNonRevProof)
	}

	if a.SignatureProof.IssuerAuthClaimMTP == nil {
		return nil, errors.New(ErrorEmptyIssuerAuthClaimProof)
	}

	if a.SignatureProof.IssuerAuthNonRevProof.Proof == nil {
		return nil, errors.New(ErrorEmptyIssuerAuthClaimNonRevProof)
	}

	if a.Signature == nil {
		return nil, errors.New(ErrorEmptyChallengeSignature)
	}

	if a.SignatureProof.Signature == nil {
		return nil, errors.New(ErrorEmptyClaimSignature)
	}

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
		ClaimSchema:             a.Claim.Claim.GetSchemaHash().BigInt().String(),
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
			PrepareSiblings(a.SignatureProof.IssuerAuthClaimMTP.AllSiblings(), a.GetMTLevel())),

		IssuerAuthClaimsTreeRoot: a.SignatureProof.IssuerTreeState.ClaimsRoot,
		IssuerAuthRevTreeRoot:    a.SignatureProof.IssuerTreeState.RevocationRoot,
		IssuerAuthRootsTreeRoot:  a.SignatureProof.IssuerTreeState.RootOfRoots,

		IssuerAuthClaim: a.SignatureProof.IssuerAuthClaim,

		IssuerAuthClaimNonRevMtp: bigIntArrayToStringArray(
			PrepareSiblings(a.SignatureProof.IssuerAuthNonRevProof.Proof.AllSiblings(), a.GetMTLevel())),
	}

	values, err := PrepareCircuitArrayValues(a.Values, a.GetValueArrSize())
	if err != nil {
		return nil, err
	}
	s.Value = bigIntArrayToStringArray(values)

	nodeAuxAuth := getNodeAuxValue(a.AuthClaim.NonRevProof.Proof.NodeAux)
	s.UserAuthClaimNonRevMtpAuxHi = nodeAuxAuth.key
	s.UserAuthClaimNonRevMtpAuxHv = nodeAuxAuth.value
	s.UserAuthClaimNonRevMtpNoAux = nodeAuxAuth.noAux

	nodeAux := getNodeAuxValue(a.Claim.NonRevProof.Proof.NodeAux)
	s.IssuerClaimNonRevMtpAuxHi = nodeAux.key
	s.IssuerClaimNonRevMtpAuxHv = nodeAux.value
	s.IssuerClaimNonRevMtpNoAux = nodeAux.noAux

	issuerAuthNodeAux := getNodeAuxValue(a.SignatureProof.IssuerAuthNonRevProof.Proof.NodeAux)
	s.IssuerAuthClaimNonRevMtpAuxHi = issuerAuthNodeAux.key
	s.IssuerAuthClaimNonRevMtpAuxHv = issuerAuthNodeAux.value
	s.IssuerAuthClaimNonRevMtpNoAux = issuerAuthNodeAux.noAux

	return json.Marshal(s)
}

// AtomicQuerySigPubSignals public inputs
type AtomicQuerySigPubSignals struct {
	BaseConfig
	UserID                 *core.ID         `json:"userID"`
	UserState              *merkletree.Hash `json:"userState"`
	Challenge              *big.Int         `json:"challenge"`
	ClaimSchema            core.SchemaHash  `json:"claimSchema"`
	IssuerID               *core.ID         `json:"issuerID"`
	IssuerAuthState        *merkletree.Hash `json:"issuerAuthState"`
	IssuerClaimNonRevState *merkletree.Hash `json:"issuerClaimNonRevState"`
	SlotIndex              int              `json:"slotIndex"`
	ValueHash              *big.Int         `json:"valueHash"`
	Operator               int              `json:"operator"`
	Timestamp              int64            `json:"timestamp"`
}

// PubSignalsUnmarshal unmarshal credentialAtomicQuerySig.circom public signals
func (ao *AtomicQuerySigPubSignals) PubSignalsUnmarshal(data []byte) error {
	// 11 is a number of fields in AtomicQueryMTPPubSignals
	const fieldLength = 11

	var sVals []string
	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	if len(sVals) != fieldLength {
		return fmt.Errorf("invalid number of Output values expected {%d} go {%d} ", fieldLength, len(sVals))
	}

	var ok bool

	if ao.IssuerAuthState, err = merkletree.NewHashFromString(sVals[0]); err != nil {
		return err
	}

	bi, ok := big.NewInt(0).SetString(sVals[1], 10)
	if !ok {
		return fmt.Errorf("invalid value hash")
	}
	ao.ValueHash = bi

	if ao.UserID, err = idFromIntStr(sVals[2]); err != nil {
		return err
	}

	if ao.UserState, err = merkletree.NewHashFromString(sVals[3]); err != nil {
		return err
	}

	if ao.Challenge, ok = big.NewInt(0).SetString(sVals[4], 10); !ok {
		return fmt.Errorf("invalid challenge value: '%s'", sVals[0])
	}

	if ao.IssuerID, err = idFromIntStr(sVals[5]); err != nil {
		return err
	}

	if ao.IssuerClaimNonRevState, err = merkletree.NewHashFromString(sVals[6]); err != nil {
		return err
	}

	if ao.Timestamp, err = strconv.ParseInt(sVals[7], 10, 64); err != nil {
		return err
	}

	var schemaInt *big.Int
	if schemaInt, ok = big.NewInt(0).SetString(sVals[8], 10); !ok {
		return fmt.Errorf("invalid schema value: '%s'", sVals[3])
	}
	ao.ClaimSchema = core.NewSchemaHashFromInt(schemaInt)

	if ao.SlotIndex, err = strconv.Atoi(sVals[9]); err != nil {
		return err
	}

	if ao.Operator, err = strconv.Atoi(sVals[10]); err != nil {
		return err
	}

	return nil
}

// GetObjMap returns struct field as a map
func (ao AtomicQuerySigPubSignals) GetObjMap() map[string]interface{} {
	return toMap(ao)
}
