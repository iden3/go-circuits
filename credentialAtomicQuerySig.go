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

	IssuerClaimsTreeRoot *merkletree.Hash `json:"issuerClaimsTreeRoot"`
	IssuerState          *merkletree.Hash `json:"issuerState"`
	IssuerRevTreeRoot    *merkletree.Hash `json:"issuerRevTreeRoot"`
	IssuerRootsTreeRoot  *merkletree.Hash `json:"issuerRootsTreeRoot"`
}

// InputsMarshal returns Circom private inputs for credentialAtomicQuerySig.circom
func (a AtomicQuerySigInputs) InputsMarshal() ([]byte, error) {

	if a.AuthClaim.Proof == nil {
		return nil, errors.New("empty auth claim mtp proof")
	}

	if a.AuthClaim.NonRevProof == nil || a.AuthClaim.NonRevProof.Proof == nil {
		return nil, errors.New("empty auth claim non-revocation mtp proof")
	}

	if a.Claim.NonRevProof == nil || a.Claim.NonRevProof.Proof == nil {
		return nil, errors.New("empty claim non-revocation mtp proof")
	}

	if a.SignatureProof.IssuerAuthClaimMTP == nil {
		return nil, errors.New("empty issuer auth claim mtp proof")
	}

	if a.SignatureProof.IssuerAuthNonRevProof.Proof == nil {
		return nil, errors.New("empty issuer auth claim non-revocation mtp proof")
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

		IssuerClaimsTreeRoot: a.SignatureProof.IssuerTreeState.ClaimsRoot,
		IssuerState:          a.SignatureProof.IssuerTreeState.State,
		//IssuerPubKeyX:        a.SignatureProof.IssuerPublicKey.X.String(),
		//IssuerPubKeyY:        a.SignatureProof.IssuerPublicKey.Y.String(),
		IssuerRevTreeRoot:   a.SignatureProof.IssuerTreeState.RevocationRoot,
		IssuerRootsTreeRoot: a.SignatureProof.IssuerTreeState.RootOfRoots,
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
	IssuerState            *merkletree.Hash `json:"issuerState"`
	IssuerAuthState        *merkletree.Hash `json:"issuerAuthState"`
	IssuerClaimNonRevState *merkletree.Hash `json:"issuerClaimNonRevState"`
	SlotIndex              int              `json:"slotIndex"`
	Values                 []*big.Int       `json:"values"`
	Operator               int              `json:"operator"`
	Timestamp              int64            `json:"timestamp"`
}

// PubSignalsUnmarshal unmarshal credentialAtomicQuerySig.circom public signals
func (ao *AtomicQuerySigPubSignals) PubSignalsUnmarshal(data []byte) error {
	// 11 is a number of fields in AtomicQuerySigPubSignals before values, values is last element in the proof and
	// it is length could be different base on the circuit configuration. The length could be modified by set value
	// in ValueArraySize
	const fieldLength = 11

	var sVals []string
	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	if len(sVals) != fieldLength+ao.GetValueArrSize() {
		return fmt.Errorf("invalid number of Output values expected {%d} go {%d} ", 11+ao.GetValueArrSize(), len(sVals))
	}

	if ao.IssuerAuthState, err = merkletree.NewHashFromString(sVals[0]); err != nil {
		return err
	}

	if ao.UserID, err = idFromIntStr(sVals[1]); err != nil {
		return err
	}

	if ao.UserState, err = merkletree.NewHashFromString(sVals[2]); err != nil {
		return err
	}

	var ok bool
	if ao.Challenge, ok = big.NewInt(0).SetString(sVals[3], 10); !ok {
		return fmt.Errorf("invalid challenge value: '%s'", sVals[0])
	}

	if ao.IssuerID, err = idFromIntStr(sVals[4]); err != nil {
		return err
	}

	if ao.IssuerState, err = merkletree.NewHashFromString(sVals[5]); err != nil {
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

	for i, v := range sVals[fieldLength : fieldLength+ao.GetValueArrSize()] {
		bi, ok := big.NewInt(0).SetString(v, 10)
		if !ok {
			return fmt.Errorf("invalid value in index: %d", i)
		}
		ao.Values = append(ao.Values, bi)
	}

	return nil
}

// GetObjMap returns struct field as a map
func (ao AtomicQuerySigPubSignals) GetObjMap() map[string]interface{} {
	return toMap(ao)
}
