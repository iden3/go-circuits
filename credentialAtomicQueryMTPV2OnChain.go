package circuits

import (
	"encoding/json"
	"fmt"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"math/big"
	"strconv"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/pkg/errors"
)

// AtomicQueryMTPV2OnChainInputs ZK private inputs for credentialAtomicQueryMTPV2OnChain.circom
type AtomicQueryMTPV2OnChainInputs struct {
	BaseConfig
	// auth
	ID                       *core.ID
	ProfileNonce             *big.Int
	ClaimSubjectProfileNonce *big.Int

	Claim                    ClaimWithMTPProof // claim issued for user
	SkipClaimRevocationCheck bool

	RequestID *big.Int

	CurrentTimeStamp int64

	AuthClaim *core.Claim `json:"authClaim"`

	AuthClaimIncMtp    *merkletree.Proof `json:"authClaimIncMtp"`
	AuthClaimNonRevMtp *merkletree.Proof `json:"authClaimNonRevMtp"`
	TreeState          TreeState         `json:"treeState"`

	GISTProof GISTProof `json:"gistProof"`

	Signature *babyjub.Signature `json:"signature"`
	Challenge *big.Int           `json:"challenge"`

	// query
	Query
}

// atomicQueryMTPV2OnChainCircuitInputs type represents credentialAtomicQueryMTP.circom private inputs required by prover
type atomicQueryMTPV2OnChainCircuitInputs struct {
	RequestID string `json:"requestID"`

	// user data
	UserGenesisID            string `json:"userGenesisID"`            //
	ProfileNonce             string `json:"profileNonce"`             //
	ClaimSubjectProfileNonce string `json:"claimSubjectProfileNonce"` //

	IssuerID string `json:"issuerID"`
	// Claim
	IssuerClaim *core.Claim `json:"issuerClaim"`
	// Inclusion
	IssuerClaimMtp            []*merkletree.Hash `json:"issuerClaimMtp"`
	IssuerClaimClaimsTreeRoot *merkletree.Hash   `json:"issuerClaimClaimsTreeRoot"`
	IssuerClaimRevTreeRoot    *merkletree.Hash   `json:"issuerClaimRevTreeRoot"`
	IssuerClaimRootsTreeRoot  *merkletree.Hash   `json:"issuerClaimRootsTreeRoot"`
	IssuerClaimIdenState      *merkletree.Hash   `json:"issuerClaimIdenState"`

	IssuerClaimNonRevClaimsTreeRoot *merkletree.Hash   `json:"issuerClaimNonRevClaimsTreeRoot"`
	IssuerClaimNonRevRevTreeRoot    *merkletree.Hash   `json:"issuerClaimNonRevRevTreeRoot"`
	IssuerClaimNonRevRootsTreeRoot  *merkletree.Hash   `json:"issuerClaimNonRevRootsTreeRoot"`
	IssuerClaimNonRevState          *merkletree.Hash   `json:"issuerClaimNonRevState"`
	IssuerClaimNonRevMtp            []*merkletree.Hash `json:"issuerClaimNonRevMtp"`
	IssuerClaimNonRevMtpAuxHi       *merkletree.Hash   `json:"issuerClaimNonRevMtpAuxHi"`
	IssuerClaimNonRevMtpAuxHv       *merkletree.Hash   `json:"issuerClaimNonRevMtpAuxHv"`
	IssuerClaimNonRevMtpNoAux       string             `json:"issuerClaimNonRevMtpNoAux"`

	IsRevocationChecked int `json:"isRevocationChecked"`

	ClaimSchema string `json:"claimSchema"`

	// Query
	// JSON path
	ClaimPathNotExists int                `json:"claimPathNotExists"` // 0 for inclusion, 1 for non-inclusion
	ClaimPathMtp       []*merkletree.Hash `json:"claimPathMtp"`
	ClaimPathMtpNoAux  string             `json:"claimPathMtpNoAux"` // 1 if aux node is empty,
	// 0 if non-empty or for inclusion proofs
	ClaimPathMtpAuxHi *merkletree.Hash `json:"claimPathMtpAuxHi"` // 0 for inclusion proof
	ClaimPathMtpAuxHv *merkletree.Hash `json:"claimPathMtpAuxHv"` // 0 for inclusion proof
	ClaimPathKey      string           `json:"claimPathKey"`      // hash of path in merklized json-ld document
	ClaimPathValue    string           `json:"claimPathValue"`    // value in this path in merklized json-ld document

	Operator  int      `json:"operator"`
	SlotIndex int      `json:"slotIndex"`
	Timestamp int64    `json:"timestamp"`
	Value     []string `json:"value"`

	// AuthClaim proof of inclusion
	AuthClaim    *core.Claim        `json:"authClaim"`
	AuthClaimMtp []*merkletree.Hash `json:"authClaimIncMtp"`

	// AuthClaim non revocation proof
	AuthClaimNonRevMtp      []*merkletree.Hash `json:"authClaimNonRevMtp"`
	AuthClaimNonRevMtpAuxHi *merkletree.Hash   `json:"authClaimNonRevMtpAuxHi"`
	AuthClaimNonRevMtpAuxHv *merkletree.Hash   `json:"authClaimNonRevMtpAuxHv"`
	AuthClaimNonRevMtpNoAux string             `json:"authClaimNonRevMtpNoAux"`

	Challenge             string `json:"challenge"`
	ChallengeSignatureR8X string `json:"challengeSignatureR8x"`
	ChallengeSignatureR8Y string `json:"challengeSignatureR8y"`
	ChallengeSignatureS   string `json:"challengeSignatureS"`

	// User State
	ClaimsTreeRoot *merkletree.Hash `json:"userClaimsTreeRoot"`
	RevTreeRoot    *merkletree.Hash `json:"userRevTreeRoot"`
	RootsTreeRoot  *merkletree.Hash `json:"userRootsTreeRoot"`
	State          *merkletree.Hash `json:"userState"`

	// Global on-cain state
	GISTRoot     *merkletree.Hash   `json:"gistRoot"`
	GISTMtp      []*merkletree.Hash `json:"gistMtp"`
	GISTMtpAuxHi *merkletree.Hash   `json:"gistMtpAuxHi"`
	GISTMtpAuxHv *merkletree.Hash   `json:"gistMtpAuxHv"`
	GISTMtpNoAux string             `json:"gistMtpNoAux"`
}

// Validate validates AtomicQueryMTPPubSignals
func (a AtomicQueryMTPV2OnChainInputs) Validate() error {

	if a.RequestID == nil {
		return errors.New(ErrorEmptyRequestID)
	}

	if a.AuthClaimIncMtp == nil {
		return errors.New(ErrorEmptyAuthClaimProof)
	}

	if a.AuthClaimNonRevMtp == nil {
		return errors.New(ErrorEmptyAuthClaimNonRevProof)
	}

	if a.GISTProof.Proof == nil {
		return errors.New(ErrorEmptyGlobalProof)
	}

	if a.Signature == nil {
		return errors.New(ErrorEmptyChallengeSignature)
	}

	if a.Challenge == nil {
		return errors.New(ErrorEmptyChallenge)
	}

	return nil
}

// InputsMarshal returns Circom private inputs for credentialAtomicQueryMTP.circom
func (a AtomicQueryMTPV2OnChainInputs) InputsMarshal() ([]byte, error) {
	if err := a.Validate(); err != nil {
		return nil, err
	}

	if a.Query.ValueProof != nil {
		if err := a.Query.validate(); err != nil {
			return nil, err
		}
		if err := a.Query.ValueProof.validate(); err != nil {
			return nil, err
		}
	}

	valueProof := a.Query.ValueProof
	if valueProof == nil {
		valueProof = &ValueProof{}
		valueProof.Path = big.NewInt(0)
		valueProof.Value = big.NewInt(0)
		valueProof.MTP = &merkletree.Proof{}
	}

	s := atomicQueryMTPV2OnChainCircuitInputs{
		RequestID:                       a.RequestID.String(),
		UserGenesisID:                   a.ID.BigInt().String(),
		ProfileNonce:                    a.ProfileNonce.String(),
		ClaimSubjectProfileNonce:        a.ClaimSubjectProfileNonce.String(),
		IssuerID:                        a.Claim.IssuerID.BigInt().String(),
		IssuerClaim:                     a.Claim.Claim,
		IssuerClaimMtp:                  CircomSiblings(a.Claim.IncProof.Proof, a.GetMTLevel()),
		IssuerClaimClaimsTreeRoot:       a.Claim.IncProof.TreeState.ClaimsRoot,
		IssuerClaimRevTreeRoot:          a.Claim.IncProof.TreeState.RevocationRoot,
		IssuerClaimRootsTreeRoot:        a.Claim.IncProof.TreeState.RootOfRoots,
		IssuerClaimIdenState:            a.Claim.IncProof.TreeState.State,
		IssuerClaimNonRevMtp:            CircomSiblings(a.Claim.NonRevProof.Proof, a.GetMTLevel()),
		IssuerClaimNonRevClaimsTreeRoot: a.Claim.NonRevProof.TreeState.ClaimsRoot,
		IssuerClaimNonRevRevTreeRoot:    a.Claim.NonRevProof.TreeState.RevocationRoot,
		IssuerClaimNonRevRootsTreeRoot:  a.Claim.NonRevProof.TreeState.RootOfRoots,
		IssuerClaimNonRevState:          a.Claim.NonRevProof.TreeState.State,
		ClaimSchema:                     a.Claim.Claim.GetSchemaHash().BigInt().String(),
		ClaimPathMtp:                    CircomSiblings(valueProof.MTP, a.GetMTLevel()),
		ClaimPathValue:                  valueProof.Value.String(),
		Operator:                        a.Operator,
		SlotIndex:                       a.SlotIndex,
		Timestamp:                       a.CurrentTimeStamp,
		IsRevocationChecked:             1,

		AuthClaim: a.AuthClaim,
		AuthClaimMtp: merkletree.CircomSiblingsFromSiblings(a.AuthClaimIncMtp.AllSiblings(),
			a.GetMTLevel()-1),
		AuthClaimNonRevMtp: merkletree.CircomSiblingsFromSiblings(a.AuthClaimNonRevMtp.AllSiblings(),
			a.GetMTLevel()-1),
		Challenge:             a.Challenge.String(),
		ChallengeSignatureR8X: a.Signature.R8.X.String(),
		ChallengeSignatureR8Y: a.Signature.R8.Y.String(),
		ChallengeSignatureS:   a.Signature.S.String(),
		ClaimsTreeRoot:        a.TreeState.ClaimsRoot,
		RevTreeRoot:           a.TreeState.RevocationRoot,
		RootsTreeRoot:         a.TreeState.RootOfRoots,
		State:                 a.TreeState.State,
		GISTRoot:              a.GISTProof.Root,
		GISTMtp: merkletree.CircomSiblingsFromSiblings(a.GISTProof.Proof.AllSiblings(),
			a.GetMTLevelOnChain()-1),
	}

	if a.SkipClaimRevocationCheck {
		s.IsRevocationChecked = 0
	}

	nodeAux := GetNodeAuxValue(a.Claim.NonRevProof.Proof)
	s.IssuerClaimNonRevMtpAuxHi = nodeAux.key
	s.IssuerClaimNonRevMtpAuxHv = nodeAux.value
	s.IssuerClaimNonRevMtpNoAux = nodeAux.noAux

	s.ClaimPathNotExists = existenceToInt(valueProof.MTP.Existence)
	nodAuxJSONLD := GetNodeAuxValue(valueProof.MTP)
	s.ClaimPathMtpNoAux = nodAuxJSONLD.noAux
	s.ClaimPathMtpAuxHi = nodAuxJSONLD.key
	s.ClaimPathMtpAuxHv = nodAuxJSONLD.value

	s.ClaimPathKey = valueProof.Path.String()

	values, err := PrepareCircuitArrayValues(a.Values, a.GetValueArrSize())
	if err != nil {
		return nil, err
	}
	s.Value = bigIntArrayToStringArray(values)

	nodeAuxAuth := GetNodeAuxValue(a.AuthClaimNonRevMtp)
	s.AuthClaimNonRevMtpAuxHi = nodeAuxAuth.key
	s.AuthClaimNonRevMtpAuxHv = nodeAuxAuth.value
	s.AuthClaimNonRevMtpNoAux = nodeAuxAuth.noAux

	globalNodeAux := GetNodeAuxValue(a.GISTProof.Proof)
	s.GISTMtpAuxHi = globalNodeAux.key
	s.GISTMtpAuxHv = globalNodeAux.value
	s.GISTMtpNoAux = globalNodeAux.noAux

	return json.Marshal(s)
}

// AtomicQueryMTPPubSignals public signals
type AtomicQueryMTPV2OnChainPubSignals struct {
	BaseConfig
	RequestID              *big.Int         `json:"requestID"`
	UserID                 *core.ID         `json:"userID"`
	IssuerID               *core.ID         `json:"issuerID"`
	IssuerClaimIdenState   *merkletree.Hash `json:"issuerClaimIdenState"`
	IssuerClaimNonRevState *merkletree.Hash `json:"issuerClaimNonRevState"`
	ClaimSchema            core.SchemaHash  `json:"claimSchema"`
	SlotIndex              int              `json:"slotIndex"`
	Operator               int              `json:"operator"`
	Timestamp              int64            `json:"timestamp"`
	Merklized              int              `json:"merklized"`
	ClaimPathKey           *big.Int         `json:"claimPathKey"`
	ClaimPathNotExists     int              `json:"claimPathNotExists"`  // 0 for inclusion, 1 for non-inclusion
	IsRevocationChecked    int              `json:"isRevocationChecked"` // 0 revocation not check, // 1 for check revocation
	ValueHash              *big.Int         `json:"valueHash"`
	Challenge              *big.Int         `json:"challenge"`
	GlobalRoot             *merkletree.Hash `json:"gistRoot"`
}

// PubSignalsUnmarshal unmarshal credentialAtomicQueryMTPV2OnChain.circom public signals array to AtomicQueryMTPPubSignals
func (ao *AtomicQueryMTPV2OnChainPubSignals) PubSignalsUnmarshal(data []byte) error {

	// expected order:
	//merklized
	//userID
	//valueHash
	//requestID
	//challenge
	//gistRoot
	//issuerID
	//issuerClaimIdenState
	//isRevocationChecked
	//issuerClaimNonRevState
	//timestamp
	//claimSchema
	//claimPathNotExists
	//claimPathKey
	//slotIndex
	//operator

	var sVals []string
	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	fieldIdx := 0

	// -- merklized
	if ao.Merklized, err = strconv.Atoi(sVals[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++

	//  - userID
	if ao.UserID, err = idFromIntStr(sVals[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++
	var ok bool

	//  - valueHash
	if ao.ValueHash, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid value hash value: '%s'", sVals[fieldIdx])
	}
	fieldIdx++

	// - requestID
	if ao.RequestID, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid requestID value: '%s'", sVals[fieldIdx])
	}
	fieldIdx++

	// - challenge

	if ao.Challenge, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid challenge value: '%s'", sVals[fieldIdx])
	}
	fieldIdx++

	// - gistRoot
	if ao.GlobalRoot, err = merkletree.NewHashFromString(sVals[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++

	// - issuerID
	if ao.IssuerID, err = idFromIntStr(sVals[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++

	// - issuerClaimIdenState
	if ao.IssuerClaimIdenState, err = merkletree.NewHashFromString(sVals[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++

	// - isRevocationChecked
	if ao.IsRevocationChecked, err = strconv.Atoi(sVals[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++

	// - issuerClaimNonRevState
	if ao.IssuerClaimNonRevState, err = merkletree.NewHashFromString(sVals[fieldIdx]); err != nil {
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
		return fmt.Errorf("invalid schema value: '%s'", sVals[fieldIdx])
	}
	ao.ClaimSchema = core.NewSchemaHashFromInt(schemaInt)
	fieldIdx++

	// - ClaimPathNotExists
	if ao.ClaimPathNotExists, err = strconv.Atoi(sVals[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++

	// - ClaimPathKey
	if ao.ClaimPathKey, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid claimPathKey: %s", sVals[fieldIdx])
	}
	fieldIdx++

	// - slotIndex
	if ao.SlotIndex, err = strconv.Atoi(sVals[fieldIdx]); err != nil {
		return err
	}
	fieldIdx++

	// - operator
	if ao.Operator, err = strconv.Atoi(sVals[fieldIdx]); err != nil {
		return err
	}

	return nil
}

// GetObjMap returns struct field as a map
func (ao AtomicQueryMTPV2OnChainPubSignals) GetObjMap() map[string]interface{} {
	return toMap(ao)
}
