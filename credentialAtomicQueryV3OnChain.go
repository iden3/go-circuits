package circuits

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/pkg/errors"
)

// AtomicQueryV3OnChainInputs ZK private inputs for credentialAtomicQueryV3OnChain.circom
type AtomicQueryV3OnChainInputs struct {
	BaseConfig

	RequestID *big.Int

	ID                       *core.ID
	ProfileNonce             *big.Int
	ClaimSubjectProfileNonce *big.Int

	Claim                    ClaimWithSigAndMTPProof
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

	ProofType ProofType

	LinkNonce *big.Int
}

// atomicQueryV3OnChainCircuitInputs type represents credentialAtomicQueryV3OnChain.circom private inputs required by prover
type atomicQueryV3OnChainCircuitInputs struct {
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

	IssuerClaimMtp            []*merkletree.Hash `json:"issuerClaimMtp"`
	IssuerClaimClaimsTreeRoot *merkletree.Hash   `json:"issuerClaimClaimsTreeRoot"`
	IssuerClaimRevTreeRoot    *merkletree.Hash   `json:"issuerClaimRevTreeRoot"`
	IssuerClaimRootsTreeRoot  *merkletree.Hash   `json:"issuerClaimRootsTreeRoot"`
	IssuerClaimIdenState      *merkletree.Hash   `json:"issuerClaimIdenState"`

	ProofType string `json:"proofType"`

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

	// Private random nonce, used to generate LinkID
	LinkNonce string `json:"linkNonce"`
}

func (a AtomicQueryV3OnChainInputs) Validate() error {

	if a.RequestID == nil {
		return errors.New(ErrorEmptyRequestID)
	}

	if a.Claim.NonRevProof.Proof == nil {
		return errors.New(ErrorEmptyClaimNonRevProof)
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

	switch a.ProofType {
	case SigProotType:
		if a.Claim.SignatureProof.IssuerAuthIncProof.Proof == nil {
			return errors.New(ErrorEmptyIssuerAuthClaimProof)
		}

		if a.Claim.SignatureProof.IssuerAuthNonRevProof.Proof == nil {
			return errors.New(ErrorEmptyIssuerAuthClaimNonRevProof)
		}

		if a.Claim.SignatureProof.Signature == nil {
			return errors.New(ErrorEmptyClaimSignature)
		}
	case MTPProofType:
		if a.Claim.IncProof.Proof == nil {
			return errors.New(ErrorEmptyClaimProof)
		}
	default:
		return errors.New(ErrorInvalidProofType)
	}

	return nil
}

// InputsMarshal returns Circom private inputs for credentialAtomicQueryV3OnChain.circom
func (a AtomicQueryV3OnChainInputs) InputsMarshal() ([]byte, error) {

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

	s := atomicQueryV3OnChainCircuitInputs{
		RequestID:                a.RequestID.String(),
		UserGenesisID:            a.ID.BigInt().String(),
		ProfileNonce:             a.ProfileNonce.String(),
		ClaimSubjectProfileNonce: a.ClaimSubjectProfileNonce.String(),
		IssuerID:                 a.Claim.IssuerID.BigInt().String(),
		IssuerClaim:              a.Claim.Claim,

		IssuerClaimNonRevClaimsTreeRoot: a.Claim.NonRevProof.TreeState.ClaimsRoot.BigInt().String(),
		IssuerClaimNonRevRevTreeRoot:    a.Claim.NonRevProof.TreeState.RevocationRoot.BigInt().String(),
		IssuerClaimNonRevRootsTreeRoot:  a.Claim.NonRevProof.TreeState.RootOfRoots.BigInt().String(),
		IssuerClaimNonRevState:          a.Claim.NonRevProof.TreeState.State.BigInt().String(),
		IssuerClaimNonRevMtp: PrepareSiblingsStr(a.Claim.NonRevProof.Proof.AllSiblings(),
			a.GetMTLevel()),

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

	switch a.ProofType {
	case SigProotType:
		s.ProofType = "0"

		s.IssuerClaimSignatureR8X = a.Claim.SignatureProof.Signature.R8.X.String()
		s.IssuerClaimSignatureR8Y = a.Claim.SignatureProof.Signature.R8.Y.String()
		s.IssuerClaimSignatureS = a.Claim.SignatureProof.Signature.S.String()
		s.IssuerAuthClaim = a.Claim.SignatureProof.IssuerAuthClaim
		s.IssuerAuthClaimMtp = PrepareSiblingsStr(a.Claim.SignatureProof.IssuerAuthIncProof.Proof.AllSiblings(),
			a.GetMTLevel())
		s.IssuerAuthClaimsTreeRoot = a.Claim.SignatureProof.IssuerAuthIncProof.TreeState.ClaimsRoot.
			BigInt().String()
		s.IssuerAuthRevTreeRoot = a.Claim.SignatureProof.IssuerAuthIncProof.TreeState.RevocationRoot.BigInt().String()
		s.IssuerAuthRootsTreeRoot = a.Claim.SignatureProof.IssuerAuthIncProof.TreeState.RootOfRoots.BigInt().String()
		s.IssuerAuthClaimNonRevMtp = PrepareSiblingsStr(a.Claim.SignatureProof.IssuerAuthNonRevProof.Proof.
			AllSiblings(), a.GetMTLevel())

		nodeAuxIssuerAuthNonRev := GetNodeAuxValue(a.Claim.SignatureProof.IssuerAuthNonRevProof.Proof)
		s.IssuerAuthClaimNonRevMtpAuxHi = nodeAuxIssuerAuthNonRev.key
		s.IssuerAuthClaimNonRevMtpAuxHv = nodeAuxIssuerAuthNonRev.value
		s.IssuerAuthClaimNonRevMtpNoAux = nodeAuxIssuerAuthNonRev.noAux

		a.fillMTPProofsWithZero(&s)
	case MTPProofType:
		s.ProofType = "1"

		s.IssuerClaimMtp = CircomSiblings(a.Claim.IncProof.Proof, a.GetMTLevel())
		s.IssuerClaimClaimsTreeRoot = a.Claim.IncProof.TreeState.ClaimsRoot
		s.IssuerClaimRevTreeRoot = a.Claim.IncProof.TreeState.RevocationRoot
		s.IssuerClaimRootsTreeRoot = a.Claim.IncProof.TreeState.RootOfRoots
		s.IssuerClaimIdenState = a.Claim.IncProof.TreeState.State

		a.fillSigProofWithZero(&s)
	}

	nodeAuxNonRev := GetNodeAuxValue(a.Claim.NonRevProof.Proof)
	s.IssuerClaimNonRevMtpAuxHi = nodeAuxNonRev.key
	s.IssuerClaimNonRevMtpAuxHv = nodeAuxNonRev.value
	s.IssuerClaimNonRevMtpNoAux = nodeAuxNonRev.noAux

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

	s.LinkNonce = a.LinkNonce.String()

	return json.Marshal(s)
}

func (a AtomicQueryV3OnChainInputs) fillMTPProofsWithZero(s *atomicQueryV3OnChainCircuitInputs) {
	s.IssuerClaimMtp = CircomSiblings(&merkletree.Proof{}, a.GetMTLevel())
	s.IssuerClaimClaimsTreeRoot = &merkletree.HashZero
	s.IssuerClaimRevTreeRoot = &merkletree.HashZero
	s.IssuerClaimRootsTreeRoot = &merkletree.HashZero
	s.IssuerClaimIdenState = &merkletree.HashZero
}

func (a AtomicQueryV3OnChainInputs) fillSigProofWithZero(s *atomicQueryV3OnChainCircuitInputs) {
	s.IssuerClaimSignatureR8X = "0"
	s.IssuerClaimSignatureR8Y = "0"
	s.IssuerClaimSignatureS = "0"
	s.IssuerAuthClaim = &core.Claim{}
	s.IssuerAuthClaimMtp = PrepareSiblingsStr([]*merkletree.Hash{}, a.GetMTLevel())
	s.IssuerAuthClaimsTreeRoot = "0"
	s.IssuerAuthRevTreeRoot = "0"
	s.IssuerAuthRootsTreeRoot = "0"
	s.IssuerAuthClaimNonRevMtp = PrepareSiblingsStr([]*merkletree.Hash{}, a.GetMTLevel())

	s.IssuerAuthClaimNonRevMtpAuxHi = &merkletree.HashZero
	s.IssuerAuthClaimNonRevMtpAuxHv = &merkletree.HashZero
	s.IssuerAuthClaimNonRevMtpNoAux = "0"
}

// AtomicQueryV3OnChainPubSignals public inputs
type AtomicQueryV3OnChainPubSignals struct {
	BaseConfig
	RequestID              *big.Int         `json:"requestID"`
	UserID                 *core.ID         `json:"userID"`
	IssuerID               *core.ID         `json:"issuerID"`
	IssuerClaimIdenState   *merkletree.Hash `json:"issuerClaimIdenState"`
	IssuerClaimNonRevState *merkletree.Hash `json:"issuerClaimNonRevState"`
	Timestamp              int64            `json:"timestamp"`
	Merklized              int              `json:"merklized"`
	IsRevocationChecked    int              `json:"isRevocationChecked"` // 0 revocation not check, // 1 for check revocation
	QueryHash              *big.Int         `json:"circuitQueryHash"`
	Challenge              *big.Int         `json:"challenge"`
	GlobalRoot             *merkletree.Hash `json:"gistRoot"`
	ProofType              int              `json:"proofType"`
	IssuerAuthState        *merkletree.Hash `json:"issuerAuthState"`
	// OperatorOutput         *big.Int         `son:"operatorOutput"`
	LinkID *big.Int `json:"linkID"`
}

// PubSignalsUnmarshal unmarshal credentialAtomicQueryV3OnChain.circom public signals
func (ao *AtomicQueryV3OnChainPubSignals) PubSignalsUnmarshal(data []byte) error {
	// expected order:
	// merklized
	// userID
	// circuitQueryHash
	// linkID
	// issuerAuthState // sig specific
	// proofType
	// requestID
	// challenge
	// gistRoot
	// issuerID
	// isRevocationChecked
	// issuerClaimNonRevState
	// timestamp
	// issuerClaimIdenState // mtp specific
	// operatorOutput

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
		return fmt.Errorf("invalid circuits query hash value: '%s'", sVals[fieldIdx])
	}
	fieldIdx++

	// - operatorOutput
	// if ao.OperatorOutput, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
	// 	return fmt.Errorf("invalid operator output value: '%s'", sVals[fieldIdx])
	// }
	// fieldIdx++

	// - linkID
	if ao.LinkID, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid link ID value: '%s'", sVals[fieldIdx])
	}
	fieldIdx++

	// - issuerAuthState
	if ao.IssuerAuthState, err = merkletree.NewHashFromString(sVals[fieldIdx]); err != nil {
		return fmt.Errorf("invalid issuerAuthState value: '%s'", sVals[fieldIdx])
	}
	fieldIdx++

	// - proofType
	if ao.ProofType, err = strconv.Atoi(sVals[fieldIdx]); err != nil {
		return fmt.Errorf("invalid proofType value: '%s'", sVals[fieldIdx])
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
	fieldIdx++

	// - IssuerClaimIdenState
	if ao.IssuerClaimIdenState, err = merkletree.NewHashFromString(sVals[fieldIdx]); err != nil {
		return fmt.Errorf("invalid IssuerClaimIdenState value: '%s'", sVals[fieldIdx])
	}

	return nil
}

// GetObjMap returns struct field as a map
func (ao AtomicQueryV3OnChainPubSignals) GetObjMap() map[string]interface{} {
	return toMap(ao)
}
