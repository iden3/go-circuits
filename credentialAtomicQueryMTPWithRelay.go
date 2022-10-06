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

// AtomicQueryMTPWithRelayInputs ZK private inputs for credentialAtomicQueryMTPWithRelay.circom
type AtomicQueryMTPWithRelayInputs struct {
	BaseConfig

	// auth
	ID        *core.ID
	AuthClaim ClaimWithMTPProof
	Challenge *big.Int
	Signature *babyjub.Signature

	// relay
	UserStateInRelayClaim ClaimWithMTPProof

	// claim
	Claim ClaimWithMTPProof

	CurrentTimeStamp int64

	// query
	Query
}

// atomicQueryMTPWithRelayCircuitInputs type represents credentialAtomicQueryMTPWithRelay.circom
type atomicQueryMTPWithRelayCircuitInputs struct {
	UserAuthClaim               *core.Claim      `json:"userAuthClaim"`
	UserAuthClaimMtp            []string         `json:"userAuthClaimMtp"`
	UserAuthClaimNonRevMtp      []string         `json:"userAuthClaimNonRevMtp"`
	UserAuthClaimNonRevMtpAuxHi *merkletree.Hash `json:"userAuthClaimNonRevMtpAuxHi"`
	UserAuthClaimNonRevMtpAuxHv *merkletree.Hash `json:"userAuthClaimNonRevMtpAuxHv"`
	UserAuthClaimNonRevMtpNoAux string           `json:"userAuthClaimNonRevMtpNoAux"`
	UserClaimsTreeRoot          *merkletree.Hash `json:"userClaimsTreeRoot"`
	UserRevTreeRoot             *merkletree.Hash `json:"userRevTreeRoot"`
	UserRootsTreeRoot           *merkletree.Hash `json:"userRootsTreeRoot"`
	UserID                      string           `json:"userID"`

	Challenge             string `json:"challenge"`
	ChallengeSignatureR8X string `json:"challengeSignatureR8x"`
	ChallengeSignatureR8Y string `json:"challengeSignatureR8y"`
	ChallengeSignatureS   string `json:"challengeSignatureS"`

	IssuerClaim                     *core.Claim      `json:"issuerClaim"`
	IssuerClaimClaimsTreeRoot       *merkletree.Hash `json:"issuerClaimClaimsTreeRoot"`
	IssuerClaimIdenState            *merkletree.Hash `json:"issuerClaimIdenState"`
	IssuerClaimMtp                  []string         `json:"issuerClaimMtp"`
	IssuerClaimRevTreeRoot          *merkletree.Hash `json:"issuerClaimRevTreeRoot"`
	IssuerClaimRootsTreeRoot        *merkletree.Hash `json:"issuerClaimRootsTreeRoot"`
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

	RelayProofValidClaimsTreeRoot *merkletree.Hash `json:"relayProofValidClaimsTreeRoot"`
	RelayProofValidRevTreeRoot    *merkletree.Hash `json:"relayProofValidRevTreeRoot"`
	RelayProofValidRootsTreeRoot  *merkletree.Hash `json:"relayProofValidRootsTreeRoot"`
	RelayState                    *merkletree.Hash `json:"relayState"`
	UserStateInRelayClaim         *core.Claim      `json:"userStateInRelayClaim"`
	UserStateInRelayClaimMtp      []string         `json:"userStateInRelayClaimMtp"`
}

// InputsMarshal returns Circom private inputs for credentialAtomicQueryMTPWithRelay.circom
func (a AtomicQueryMTPWithRelayInputs) InputsMarshal() ([]byte, error) {

	if a.AuthClaim.Proof == nil {
		return nil, errors.New(ErrorEmptyAuthClaimProof)
	}

	if a.AuthClaim.NonRevProof == nil || a.AuthClaim.NonRevProof.Proof == nil {
		return nil, errors.New(ErrorEmptyAuthClaimNonRevProof)
	}

	if a.Claim.Proof == nil {
		return nil, errors.New(ErrorEmptyClaimProof)
	}

	if a.Claim.NonRevProof == nil || a.Claim.NonRevProof.Proof == nil {
		return nil, errors.New(ErrorEmptyClaimNonRevProof)
	}

	if a.UserStateInRelayClaim.Proof == nil {
		return nil, errors.New(ErrorUserStateInRelayClaimProof)
	}

	if a.Signature == nil {
		return nil, errors.New(ErrorEmptyChallengeSignature)
	}

	s := atomicQueryMTPWithRelayCircuitInputs{
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
		IssuerClaimClaimsTreeRoot:       a.Claim.TreeState.ClaimsRoot,
		IssuerClaimIdenState:            a.Claim.TreeState.State,
		IssuerClaimMtp:                  PrepareSiblingsStr(a.Claim.Proof.AllSiblings(), a.GetMTLevel()),
		IssuerClaimRevTreeRoot:          a.Claim.TreeState.RevocationRoot,
		IssuerClaimRootsTreeRoot:        a.Claim.TreeState.RootOfRoots,
		IssuerClaimNonRevClaimsTreeRoot: a.Claim.NonRevProof.TreeState.ClaimsRoot,
		IssuerClaimNonRevRevTreeRoot:    a.Claim.NonRevProof.TreeState.RevocationRoot,
		IssuerClaimNonRevRootsTreeRoot:  a.Claim.NonRevProof.TreeState.RootOfRoots,
		IssuerClaimNonRevState:          a.Claim.NonRevProof.TreeState.State,
		IssuerClaimNonRevMtp: PrepareSiblingsStr(a.Claim.NonRevProof.Proof.AllSiblings(),
			a.GetMTLevel()),
		ClaimSchema:        a.Claim.Claim.GetSchemaHash().BigInt().String(),
		UserClaimsTreeRoot: a.AuthClaim.TreeState.ClaimsRoot,
		UserRevTreeRoot:    a.AuthClaim.TreeState.RevocationRoot,
		UserRootsTreeRoot:  a.AuthClaim.TreeState.RootOfRoots,
		UserID:             a.ID.BigInt().String(),
		IssuerID:           a.Claim.IssuerID.BigInt().String(),
		Operator:           a.Operator,
		SlotIndex:          a.SlotIndex,
		Timestamp:          a.CurrentTimeStamp,

		RelayProofValidClaimsTreeRoot: a.UserStateInRelayClaim.TreeState.ClaimsRoot,
		RelayProofValidRevTreeRoot:    a.UserStateInRelayClaim.TreeState.RevocationRoot,
		RelayProofValidRootsTreeRoot:  a.UserStateInRelayClaim.TreeState.RootOfRoots,
		RelayState:                    a.UserStateInRelayClaim.TreeState.State,
		UserStateInRelayClaim:         a.UserStateInRelayClaim.Claim,
		UserStateInRelayClaimMtp: bigIntArrayToStringArray(
			PrepareSiblings(a.UserStateInRelayClaim.Proof.AllSiblings(), a.GetMTLevel())),
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

	return json.Marshal(s)
}

// AtomicQueryMTPWithRelayPubSignals public signals
type AtomicQueryMTPWithRelayPubSignals struct {
	BaseConfig
	UserID      *core.ID         `json:"userID"`
	RelayState  *merkletree.Hash `json:"relayState"`
	Challenge   *big.Int         `json:"challenge"`
	ClaimSchema core.SchemaHash  `json:"claimSchema"`
	SlotIndex   int              `json:"slotIndex"`
	Operator    int              `json:"operator"`
	Values      []*big.Int       `json:"value"`
	Timestamp   int64            `json:"timestamp"`
	IssuerID    *core.ID         `json:"issuerID"`
}

// PubSignalsUnmarshal unmarshal credentialAtomicQueryMTPWithRelay.circom public signals
func (ao *AtomicQueryMTPWithRelayPubSignals) PubSignalsUnmarshal(data []byte) error {
	var sVals []string
	// 8 is a number of fields in AtomicQueryMTPWithRelayPubSignals before values, values is last element in the proof and
	// it is length could be different base on the circuit configuration. The length could be modified by set value
	// in ValueArraySize
	const fieldLength = 8

	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	if len(sVals) != fieldLength+ao.GetValueArrSize() {
		return fmt.Errorf("invalid number of Output values expected {%d} go {%d} ", 9, len(sVals))
	}

	if ao.UserID, err = idFromIntStr(sVals[0]); err != nil {
		return err
	}

	if ao.RelayState, err = merkletree.NewHashFromString(sVals[1]); err != nil {
		return err
	}

	var ok bool
	if ao.Challenge, ok = big.NewInt(0).SetString(sVals[2], 10); !ok {
		return fmt.Errorf("invalid challenge value: '%s'", sVals[0])
	}

	if ao.IssuerID, err = idFromIntStr(sVals[3]); err != nil {
		return err
	}

	if ao.Timestamp, err = strconv.ParseInt(sVals[4], 10, 64); err != nil {
		return err
	}

	var schemaInt *big.Int
	if schemaInt, ok = big.NewInt(0).SetString(sVals[5], 10); !ok {
		return err
	}
	ao.ClaimSchema = core.NewSchemaHashFromInt(schemaInt)

	if ao.SlotIndex, err = strconv.Atoi(sVals[6]); err != nil {
		return err
	}

	if ao.Operator, err = strconv.Atoi(sVals[7]); err != nil {
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
func (ao AtomicQueryMTPWithRelayPubSignals) GetObjMap() map[string]interface{} {
	return toMap(ao)
}
