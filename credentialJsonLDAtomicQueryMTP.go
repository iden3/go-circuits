package circuits

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/pkg/errors"
)

// JsonLDAtomicQueryMTPInputs ZK private inputs for
// credentialJsonLDAtomicQueryMTP.circom
type JsonLDAtomicQueryMTPInputs struct {
	BaseConfig
	// auth
	ID        *core.ID
	AuthClaim ClaimWithMTPProof
	Challenge *big.Int
	Signature *babyjub.Signature

	Claim ClaimWithMTPProof // claim issued for user

	CurrentTimeStamp int64

	// query
	Query JsonLDQuery
}

// stateTransitionInputsInternal type represents credentialAtomicQueryMTP.circom private inputs required by prover
type jsonLDatomicQueryMTPCircuitInputs struct {
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
	ClaimPathNotExists              int              `json:"claimPathNotExists"`
	ClaimPathMtp                    []string         `json:"claimPathMtp"`
	ClaimPathMtpNoAux               string           `json:"claimPathMtpNoAux"`
	ClaimPathMtpHi                  *merkletree.Hash `json:"claimPathMtpAuxHi"`
	ClaimPathMtpHv                  *merkletree.Hash `json:"claimPathMtpAuxHv"`
	ClaimPathKey                    string           `json:"claimPathKey"`
	ClaimPathValue                  string           `json:"claimPathValue"`
	Operator                        int              `json:"operator"`
	Timestamp                       int64            `json:"timestamp,string"`
	Value                           []string         `json:"value"`
}

// InputsMarshal returns Circom private inputs for credentialJsonLDAtomicQueryMTP.circom
func (a JsonLDAtomicQueryMTPInputs) InputsMarshal() ([]byte, error) {

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

	if a.Signature == nil {
		return nil, errors.New(ErrorEmptyChallengeSignature)
	}

	if err := a.Query.validate(); err != nil {
		return nil, err
	}

	var claimPathNotExists int
	claimPathNodeAuxValue := NodeAuxValue{
		key:   &merkletree.HashZero,
		value: &merkletree.HashZero,
		noAux: "0",
	}
	if a.Query.MTP.Existence {
		claimPathNotExists = 0
	} else {
		claimPathNotExists = 1
		claimPathNodeAuxValue = GetNodeAuxValue(a.Query.MTP)
	}

	queryPathKey, err := a.Query.Path.Key()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	s := jsonLDatomicQueryMTPCircuitInputs{
		UserAuthClaim: a.AuthClaim.Claim,
		UserAuthClaimMtp: PrepareSiblingsStr(a.AuthClaim.Proof.AllSiblings(),
			a.GetMTLevel()),
		UserAuthClaimNonRevMtp: PrepareSiblingsStr(
			a.AuthClaim.NonRevProof.Proof.AllSiblings(),
			a.GetMTLevel()),
		Challenge:                 a.Challenge.String(),
		ChallengeSignatureR8X:     a.Signature.R8.X.String(),
		ChallengeSignatureR8Y:     a.Signature.R8.Y.String(),
		ChallengeSignatureS:       a.Signature.S.String(),
		IssuerClaim:               a.Claim.Claim,
		IssuerClaimClaimsTreeRoot: a.Claim.TreeState.ClaimsRoot,
		IssuerClaimIdenState:      a.Claim.TreeState.State,
		IssuerClaimMtp: PrepareSiblingsStr(a.Claim.Proof.AllSiblings(),
			a.GetMTLevel()),
		IssuerClaimRevTreeRoot:          a.Claim.TreeState.RevocationRoot,
		IssuerClaimRootsTreeRoot:        a.Claim.TreeState.RootOfRoots,
		IssuerClaimNonRevClaimsTreeRoot: a.Claim.NonRevProof.TreeState.ClaimsRoot,
		IssuerClaimNonRevRevTreeRoot:    a.Claim.NonRevProof.TreeState.RevocationRoot,
		IssuerClaimNonRevRootsTreeRoot:  a.Claim.NonRevProof.TreeState.RootOfRoots,
		IssuerClaimNonRevState:          a.Claim.NonRevProof.TreeState.State,
		IssuerClaimNonRevMtp: PrepareSiblingsStr(
			a.Claim.NonRevProof.Proof.AllSiblings(),
			a.GetMTLevel()),
		ClaimSchema:        a.Claim.Claim.GetSchemaHash().BigInt().String(),
		UserClaimsTreeRoot: a.AuthClaim.TreeState.ClaimsRoot,
		UserState:          a.AuthClaim.TreeState.State,
		UserRevTreeRoot:    a.AuthClaim.TreeState.RevocationRoot,
		UserRootsTreeRoot:  a.AuthClaim.TreeState.RootOfRoots,
		UserID:             a.ID.BigInt().String(),
		IssuerID:           a.Claim.IssuerID.BigInt().String(),
		ClaimPathNotExists: claimPathNotExists,
		ClaimPathMtp: PrepareSiblingsStr(a.Query.MTP.AllSiblings(),
			a.GetMTLevel()),
		ClaimPathMtpNoAux: claimPathNodeAuxValue.noAux,
		ClaimPathMtpHi:    claimPathNodeAuxValue.key,
		ClaimPathMtpHv:    claimPathNodeAuxValue.value,
		ClaimPathKey:      queryPathKey.Text(10),
		ClaimPathValue:    a.Query.Value.Text(10),
		Operator:          a.Query.Operator,
		Timestamp:         a.CurrentTimeStamp,
	}

	values, err := PrepareCircuitArrayValues(a.Query.Values,
		a.GetValueArrSize())
	if err != nil {
		return nil, err
	}
	s.Value = bigIntArrayToStringArray(values)

	nodeAuxAuth := GetNodeAuxValue(a.AuthClaim.NonRevProof.Proof)
	s.UserAuthClaimNonRevMtpAuxHi = nodeAuxAuth.key
	s.UserAuthClaimNonRevMtpAuxHv = nodeAuxAuth.value
	s.UserAuthClaimNonRevMtpNoAux = nodeAuxAuth.noAux

	nodeAux := GetNodeAuxValue(a.Claim.NonRevProof.Proof)
	s.IssuerClaimNonRevMtpAuxHi = nodeAux.key
	s.IssuerClaimNonRevMtpAuxHv = nodeAux.value
	s.IssuerClaimNonRevMtpNoAux = nodeAux.noAux

	return json.Marshal(s)
}

// JsonLDAtomicQueryMTPPubSignals public signals
type JsonLDAtomicQueryMTPPubSignals struct {
	BaseConfig
	UserID                 *core.ID         `json:"userID"`
	UserState              *merkletree.Hash `json:"userState"`
	Challenge              *big.Int         `json:"challenge"`
	ClaimSchema            core.SchemaHash  `json:"claimSchema"`
	IssuerClaimIdenState   *merkletree.Hash `json:"issuerClaimIdenState"`
	IssuerClaimNonRevState *merkletree.Hash `json:"issuerClaimNonRevState"`
	IssuerID               *core.ID         `json:"issuerID"`
	ClaimPathKey           *merkletree.Hash `json:"claimPathKey"`
	Values                 []*big.Int       `json:"values"`
	Operator               int              `json:"operator"`
	Timestamp              int64            `json:"timestamp"`
}

// PubSignalsUnmarshal unmarshal credentialJsonLDAtomicQueryMTP.circom public
// signals array to JsonLDAtomicQueryMTPPubSignals
func (ao *JsonLDAtomicQueryMTPPubSignals) PubSignalsUnmarshal(data []byte) error {
	// expected order:
	//userID
	//userState
	//challenge
	//issuerID
	//timestamp
	//claimSchema
	//claimPathKey
	//operator
	//value
	//  - issuerClaimIdenState
	//  - issuerID
	//  - issuerClaimNonRevState
	//  - timestamp
	//  - claimSchema
	//  - claimPathKey
	//  - operator
	//  - values

	// 10 is a number of fields in AtomicQueryMTPPubSignals before values, values is last element in the proof and
	// it is length could be different base on the circuit configuration. The length could be modified by set value
	// in ValueArraySize
	const fieldLength = 10

	var sVals []string
	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	if len(sVals) != fieldLength+ao.GetValueArrSize() {
		return fmt.Errorf(
			"invalid number of Output values expected {%d} got {%d} ",
			fieldLength+ao.GetValueArrSize(), len(sVals))
	}

	fieldIdx := 0

	//  - userID
	if ao.UserID, err = idFromIntStr(sVals[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++

	//  - userState
	ao.UserState, err = merkletree.NewHashFromString(sVals[fieldIdx])
	if err != nil {
		return fmt.Errorf("can't get userState: %w", err)
	}
	fieldIdx++

	var ok bool
	//  - challenge
	if ao.Challenge, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid challenge value: '%s'", sVals[0])
	}
	fieldIdx++

	//  - issuerClaimIdenState
	ao.IssuerClaimIdenState, err = merkletree.NewHashFromString(sVals[fieldIdx])
	if err != nil {
		return err
	}
	fieldIdx++

	//  - issuerID
	if ao.IssuerID, err = idFromIntStr(sVals[fieldIdx]); err != nil {

		return fmt.Errorf("can't decode issuerID: %w: %v", err, sVals[fieldIdx])
	}
	fieldIdx++

	//  - issuerClaimNonRevState
	ao.IssuerClaimNonRevState, err =
		merkletree.NewHashFromString(sVals[fieldIdx])
	if err != nil {
		return err
	}
	fieldIdx++

	//  - timestamp
	ao.Timestamp, err = strconv.ParseInt(sVals[fieldIdx], 10, 64)
	if err != nil {
		return err
	}
	fieldIdx++

	//  - claimSchema
	var schemaInt *big.Int
	if schemaInt, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid schema value: '%s'", sVals[0])
	}
	ao.ClaimSchema = core.NewSchemaHashFromInt(schemaInt)
	fieldIdx++

	//  - claimPathKey
	ao.ClaimPathKey, err = merkletree.NewHashFromString(sVals[fieldIdx])
	if err != nil {
		return err
	}
	fieldIdx++

	//  - operator
	if ao.Operator, err = strconv.Atoi(sVals[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++

	//  - values
	var valuesNum = ao.GetValueArrSize()
	for i := 0; i < valuesNum; i++ {
		bi, ok := big.NewInt(0).SetString(sVals[fieldIdx], 10)
		if !ok {
			return fmt.Errorf("invalid value in index: %d", i)
		}
		ao.Values = append(ao.Values, bi)
		fieldIdx++
	}

	return nil
}

// GetObjMap returns struct field as a map
func (ao *JsonLDAtomicQueryMTPPubSignals) GetObjMap() map[string]interface{} {
	return toMap(ao)
}
