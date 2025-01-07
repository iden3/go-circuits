package circuits

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"

	"github.com/iden3/go-iden3-crypto/babyjub"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/pkg/errors"
)

// AtomicQuerySigV2OnChainInputs ZK private inputs for credentialAtomicQuerySig.circom
type AtomicQuerySigV2OnChainInputs struct {
	BaseConfig

	RequestID *big.Int

	// auth
	ID                       *core.ID
	ProfileNonce             *big.Int
	ClaimSubjectProfileNonce *big.Int

	Claim                    ClaimWithSigProof // issuerClaim
	SkipClaimRevocationCheck bool

	AuthClaim *core.Claim `json:"authClaim"`

	AuthClaimIncMtp    *merkletree.Proof `json:"authClaimIncMtp"`
	AuthClaimNonRevMtp *merkletree.Proof `json:"authClaimNonRevMtp"`
	TreeState          TreeState         `json:"treeState"`

	GISTProof GISTProof `json:"gistProof"`

	Signature *babyjub.Signature `json:"signature"`
	Challenge *big.Int           `json:"challenge"`

	// query
	Query Query

	CurrentTimeStamp int64
}

// atomicQuerySigV2OnChainCircuitInputs type represents credentialAtomicQuerySig.circom private inputs required by prover
type atomicQuerySigV2OnChainCircuitInputs struct {
	RequestID string `json:"requestID"`

	// user data
	UserGenesisID            string `json:"userGenesisID"`
	ProfileNonce             string `json:"profileNonce"`
	ClaimSubjectProfileNonce string `json:"claimSubjectProfileNonce"`

	IssuerID string `json:"issuerID"`
	// Claim
	IssuerClaim                     *core.Claim      `json:"issuerClaim"`
	IssuerClaimNonRevClaimsTreeRoot string           `json:"issuerClaimNonRevClaimsTreeRoot"`
	IssuerClaimNonRevRevTreeRoot    string           `json:"issuerClaimNonRevRevTreeRoot"`
	IssuerClaimNonRevRootsTreeRoot  string           `json:"issuerClaimNonRevRootsTreeRoot"`
	IssuerClaimNonRevState          string           `json:"issuerClaimNonRevState"`
	IssuerClaimNonRevMtp            []string         `json:"issuerClaimNonRevMtp"`
	IssuerClaimNonRevMtpAuxHi       *merkletree.Hash `json:"issuerClaimNonRevMtpAuxHi"`
	IssuerClaimNonRevMtpAuxHv       *merkletree.Hash `json:"issuerClaimNonRevMtpAuxHv"`
	IssuerClaimNonRevMtpNoAux       string           `json:"issuerClaimNonRevMtpNoAux"`
	ClaimSchema                     string           `json:"claimSchema"`
	IssuerClaimSignatureR8X         string           `json:"issuerClaimSignatureR8x"`
	IssuerClaimSignatureR8Y         string           `json:"issuerClaimSignatureR8y"`
	IssuerClaimSignatureS           string           `json:"issuerClaimSignatureS"`
	IssuerAuthClaim                 *core.Claim      `json:"issuerAuthClaim"`
	IssuerAuthClaimMtp              []string         `json:"issuerAuthClaimMtp"`
	IssuerAuthClaimNonRevMtp        []string         `json:"issuerAuthClaimNonRevMtp"`
	IssuerAuthClaimNonRevMtpAuxHi   *merkletree.Hash `json:"issuerAuthClaimNonRevMtpAuxHi"`
	IssuerAuthClaimNonRevMtpAuxHv   *merkletree.Hash `json:"issuerAuthClaimNonRevMtpAuxHv"`
	IssuerAuthClaimNonRevMtpNoAux   string           `json:"issuerAuthClaimNonRevMtpNoAux"`
	IssuerAuthClaimsTreeRoot        string           `json:"issuerAuthClaimsTreeRoot"`
	IssuerAuthRevTreeRoot           string           `json:"issuerAuthRevTreeRoot"`
	IssuerAuthRootsTreeRoot         string           `json:"issuerAuthRootsTreeRoot"`

	IsRevocationChecked int `json:"isRevocationChecked"`
	// Query
	// JSON path
	ClaimPathNotExists int              `json:"claimPathNotExists"` // 0 for inclusion, 1 for non-inclusion
	ClaimPathMtp       []string         `json:"claimPathMtp"`
	ClaimPathMtpNoAux  string           `json:"claimPathMtpNoAux"` // 1 if aux node is empty, 0 if non-empty or for inclusion proofs
	ClaimPathMtpAuxHi  *merkletree.Hash `json:"claimPathMtpAuxHi"` // 0 for inclusion proof
	ClaimPathMtpAuxHv  *merkletree.Hash `json:"claimPathMtpAuxHv"` // 0 for inclusion proof
	ClaimPathKey       string           `json:"claimPathKey"`      // hash of path in merklized json-ld document
	ClaimPathValue     string           `json:"claimPathValue"`    // value in this path in merklized json-ld document

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

func (a AtomicQuerySigV2OnChainInputs) Validate() error {

	if a.RequestID == nil {
		return errors.New(ErrorEmptyRequestID)
	}

	if a.Claim.NonRevProof.Proof == nil {
		return errors.New(ErrorEmptyClaimNonRevProof)
	}

	if a.Claim.SignatureProof.IssuerAuthIncProof.Proof == nil {
		return errors.New(ErrorEmptyIssuerAuthClaimProof)
	}

	if a.Claim.SignatureProof.IssuerAuthNonRevProof.Proof == nil {
		return errors.New(ErrorEmptyIssuerAuthClaimNonRevProof)
	}

	if a.Claim.SignatureProof.Signature == nil {
		return errors.New(ErrorEmptyClaimSignature)
	}

	if a.Query.Values == nil {
		return errors.New(ErrorEmptyQueryValue)
	}

	if a.AuthClaimIncMtp == nil {
		return errors.New(ErrorEmptyAuthClaimProof)
	}

	if a.AuthClaimNonRevMtp == nil {
		return errors.New(ErrorEmptyAuthClaimNonRevProof)
	}

	if a.GISTProof.Proof == nil {
		return errors.New(ErrorEmptyGISTProof)
	}

	if a.Signature == nil {
		return errors.New(ErrorEmptyChallengeSignature)
	}

	if a.Challenge == nil {
		return errors.New(ErrorEmptyChallenge)
	}
	return nil
}

// InputsMarshal returns Circom private inputs for credentialAtomicQuerySig.circom
func (a AtomicQuerySigV2OnChainInputs) InputsMarshal() ([]byte, error) {

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

	s := atomicQuerySigV2OnChainCircuitInputs{
		RequestID:                       a.RequestID.String(),
		UserGenesisID:                   a.ID.BigInt().String(),
		ProfileNonce:                    a.ProfileNonce.String(),
		ClaimSubjectProfileNonce:        a.ClaimSubjectProfileNonce.String(),
		IssuerID:                        a.Claim.IssuerID.BigInt().String(),
		IssuerClaim:                     a.Claim.Claim,
		IssuerClaimNonRevClaimsTreeRoot: a.Claim.NonRevProof.TreeState.ClaimsRoot.BigInt().String(),
		IssuerClaimNonRevRevTreeRoot:    a.Claim.NonRevProof.TreeState.RevocationRoot.BigInt().String(),
		IssuerClaimNonRevRootsTreeRoot:  a.Claim.NonRevProof.TreeState.RootOfRoots.BigInt().String(),
		IssuerClaimNonRevState:          a.Claim.NonRevProof.TreeState.State.BigInt().String(),
		IssuerClaimNonRevMtp: PrepareSiblingsStr(a.Claim.NonRevProof.Proof.AllSiblings(),
			a.GetMTLevel()),
		IssuerClaimSignatureR8X: a.Claim.SignatureProof.Signature.R8.X.String(),
		IssuerClaimSignatureR8Y: a.Claim.SignatureProof.Signature.R8.Y.String(),
		IssuerClaimSignatureS:   a.Claim.SignatureProof.Signature.S.String(),
		IssuerAuthClaim:         a.Claim.SignatureProof.IssuerAuthClaim,
		IssuerAuthClaimMtp: PrepareSiblingsStr(a.Claim.SignatureProof.IssuerAuthIncProof.Proof.AllSiblings(),
			a.GetMTLevel()),
		IssuerAuthClaimsTreeRoot: a.Claim.SignatureProof.IssuerAuthIncProof.TreeState.ClaimsRoot.
			BigInt().String(),
		IssuerAuthRevTreeRoot:   a.Claim.SignatureProof.IssuerAuthIncProof.TreeState.RevocationRoot.BigInt().String(),
		IssuerAuthRootsTreeRoot: a.Claim.SignatureProof.IssuerAuthIncProof.TreeState.RootOfRoots.BigInt().String(),

		IssuerAuthClaimNonRevMtp: PrepareSiblingsStr(a.Claim.SignatureProof.IssuerAuthNonRevProof.Proof.
			AllSiblings(), a.GetMTLevel()),

		ClaimSchema: a.Claim.Claim.GetSchemaHash().BigInt().String(),

		ClaimPathMtp: PrepareSiblingsStr(valueProof.MTP.AllSiblings(),
			a.GetMTLevelsClaim()),
		ClaimPathValue: valueProof.Value.Text(10),
		Operator:       a.Query.Operator,
		Timestamp:      a.CurrentTimeStamp,
		// value in this path in merklized json-ld document

		SlotIndex:           a.Query.SlotIndex,
		IsRevocationChecked: 1,

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

	nodeAuxNonRev := GetNodeAuxValue(a.Claim.NonRevProof.Proof)
	s.IssuerClaimNonRevMtpAuxHi = nodeAuxNonRev.key
	s.IssuerClaimNonRevMtpAuxHv = nodeAuxNonRev.value
	s.IssuerClaimNonRevMtpNoAux = nodeAuxNonRev.noAux

	nodeAuxIssuerAuthNonRev := GetNodeAuxValue(a.Claim.SignatureProof.IssuerAuthNonRevProof.Proof)
	s.IssuerAuthClaimNonRevMtpAuxHi = nodeAuxIssuerAuthNonRev.key
	s.IssuerAuthClaimNonRevMtpAuxHv = nodeAuxIssuerAuthNonRev.value
	s.IssuerAuthClaimNonRevMtpNoAux = nodeAuxIssuerAuthNonRev.noAux

	s.ClaimPathNotExists = existenceToInt(valueProof.MTP.Existence)
	nodAuxJSONLD := GetNodeAuxValue(valueProof.MTP)
	s.ClaimPathMtpNoAux = nodAuxJSONLD.noAux
	s.ClaimPathMtpAuxHi = nodAuxJSONLD.key
	s.ClaimPathMtpAuxHv = nodAuxJSONLD.value

	s.ClaimPathKey = valueProof.Path.String()

	values, err := PrepareCircuitArrayValues(a.Query.Values, a.GetValueArrSize())
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

func (a AtomicQuerySigV2OnChainInputs) GetStatesInfo() (StatesInfo, error) {
	if err := a.Validate(); err != nil {
		return StatesInfo{}, err
	}

	issuerID := a.Claim.IssuerID
	var issuerState merkletree.Hash
	if a.Claim.SignatureProof.IssuerAuthIncProof.TreeState.State == nil {
		return StatesInfo{}, errors.New(ErrorEmptyStateHash)
	}
	issuerState = *a.Claim.SignatureProof.IssuerAuthIncProof.TreeState.State

	if a.Claim.NonRevProof.TreeState.State == nil {
		return StatesInfo{}, errors.New(ErrorEmptyStateHash)
	}

	userID, err := core.ProfileID(*a.ID, a.ProfileNonce)
	if err != nil {
		return StatesInfo{}, err
	}

	if a.GISTProof.Root == nil {
		return StatesInfo{}, errors.New(ErrorEmptyGISTProof)
	}

	statesInfo := StatesInfo{
		States: []State{
			{
				ID:    *issuerID,
				State: issuerState,
			},
		},
		Gists: []Gist{
			{
				ID:   userID,
				Root: *a.GISTProof.Root,
			},
		},
	}

	nonRevProofState := *a.Claim.NonRevProof.TreeState.State
	if issuerState != nonRevProofState {
		statesInfo.States = append(statesInfo.States, State{
			ID:    *issuerID,
			State: nonRevProofState,
		})
	}

	return statesInfo, nil
}


// AtomicQuerySigV2OnChainPubSignals public inputs
type AtomicQuerySigV2OnChainPubSignals struct {
	BaseConfig
	RequestID              *big.Int         `json:"requestID"`
	UserID                 *core.ID         `json:"userID"`
	IssuerID               *core.ID         `json:"issuerID"`
	IssuerAuthState        *merkletree.Hash `json:"issuerAuthState"`
	IssuerClaimNonRevState *merkletree.Hash `json:"issuerClaimNonRevState"`
	Timestamp              int64            `json:"timestamp"`
	Merklized              int              `json:"merklized"`
	IsRevocationChecked    int              `json:"isRevocationChecked"` // 0 revocation not check, // 1 for check revocation
	QueryHash              *big.Int         `json:"circuitQueryHash"`
	Challenge              *big.Int         `json:"challenge"`
	GlobalRoot             *merkletree.Hash `json:"gistRoot"`
}

// PubSignalsUnmarshal unmarshal credentialAtomicQuerySig.circom public signals
func (ao *AtomicQuerySigV2OnChainPubSignals) PubSignalsUnmarshal(data []byte) error {
	// expected order:
	// merklized
	// userID
	// circuitQueryHash
	// issuerAuthState
	// requestID
	// challenge
	// gistRoot
	// issuerID
	// isRevocationChecked
	// issuerClaimNonRevState
	// timestamp
	// claimPathNotExists
	// claimPathKey

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
	if ao.QueryHash, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid value hash value: '%s'", sVals[fieldIdx])
	}
	fieldIdx++

	// - issuerAuthState
	if ao.IssuerAuthState, err = merkletree.NewHashFromString(sVals[fieldIdx]); err != nil {
		return err
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

	return nil
}

// GetObjMap returns struct field as a map
func (ao AtomicQuerySigV2OnChainPubSignals) GetObjMap() map[string]interface{} {
	return toMap(ao)
}
