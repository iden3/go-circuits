package circuits

import (
	"encoding/json"
	"fmt"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/pkg/errors"
	"math/big"
	"strconv"
)

type SybilAtomicMTPInputs struct {
	BaseConfig

	ID                       *core.ID
	ProfileNonce             *big.Int
	ClaimSubjectProfileNonce *big.Int

	IssuerClaim          ClaimWithMTPProof
	StateCommitmentClaim ClaimWithMTPProof

	GISTProof GISTProof
	CRS       *big.Int

	RequestID *big.Int
	Timestamp int64
}

type sybilAtomicMTPCircuitInputs struct {
	IssuerClaim           *core.Claim        `json:"issuerClaim"`
	IssuerClaimMtp        []*merkletree.Hash `json:"issuerClaimMtp"`
	IssuerClaimClaimsRoot *merkletree.Hash   `json:"issuerClaimClaimsRoot"`
	IssuerClaimRevRoot    *merkletree.Hash   `json:"issuerClaimRevRoot"`
	IssuerClaimRootsRoot  *merkletree.Hash   `json:"issuerClaimRootsRoot"`
	IssuerClaimIdenState  *merkletree.Hash   `json:"issuerClaimIdenState"`

	IssuerClaimNonRevMtp      []*merkletree.Hash `json:"issuerClaimNonRevMtp"`
	IssuerClaimNonRevMtpNoAux string             `json:"issuerClaimNonRevMtpNoAux"`
	IssuerClaimNonRevMtpAuxHi *merkletree.Hash   `json:"issuerClaimNonRevMtpAuxHi"`
	IssuerClaimNonRevMtpAuxHv *merkletree.Hash   `json:"issuerClaimNonRevMtpAuxHv"`

	IssuerClaimNonRevClaimsRoot *merkletree.Hash `json:"issuerClaimNonRevClaimsRoot"`
	IssuerClaimNonRevRevRoot    *merkletree.Hash `json:"issuerClaimNonRevRevRoot"`
	IssuerClaimNonRevRootsRoot  *merkletree.Hash `json:"issuerClaimNonRevRootsRoot"`
	IssuerClaimNonRevState      *merkletree.Hash `json:"issuerClaimNonRevState"`

	ClaimSchema string `json:"claimSchema"`

	StateCommitmentClaim           *core.Claim        `json:"stateCommitmentClaim"`
	StateCommitmentClaimMtp        []*merkletree.Hash `json:"stateCommitmentClaimMtp"`
	StateCommitmentClaimClaimsRoot *merkletree.Hash   `json:"stateCommitmentClaimClaimsRoot"`
	StateCommitmentClaimRevRoot    *merkletree.Hash   `json:"stateCommitmentClaimRevRoot"`
	StateCommitmentClaimRootsRoot  *merkletree.Hash   `json:"stateCommitmentClaimRootsRoot"`
	StateCommitmentClaimIdenState  *merkletree.Hash   `json:"stateCommitmentClaimIdenState"`

	GistRoot     *merkletree.Hash   `json:"gistRoot"`
	GistMtp      []*merkletree.Hash `json:"gistMtp"`
	GistMtpAuxHi *merkletree.Hash   `json:"gistMtpAuxHi"`
	GistMtpAuxHv *merkletree.Hash   `json:"gistMtpAuxHv"`
	GistMtpNoAux string             `json:"gistMtpNoAux"`

	CRS *big.Int `json:"crs"`

	UserGenesisID            string `json:"userGenesisID"`
	ProfileNonce             string `json:"profileNonce"`
	ClaimSubjectProfileNonce string `json:"claimSubjectProfileNonce"`

	RequestID *big.Int `json:"requestID"`
	IssuerID  string   `json:"issuerID"`
	Timestamp int64    `json:"timestamp"`
}

func (s SybilAtomicMTPInputs) Validate() error {

	if s.ID == nil {
		return errors.New(ErrorEmptyID)
	}

	if s.GISTProof.Proof == nil {
		return errors.New(ErrorEmptyGISTProof)
	}

	if s.IssuerClaim.Claim == nil {
		return errors.New(ErrorEmptyIssuerClaim)
	}

	if s.StateCommitmentClaim.Claim == nil {
		return errors.New(ErrorEmptyStateCommitmentClaim)
	}

	return nil
}

func (s SybilAtomicMTPInputs) InputsMarshal() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}

	mtpInputs := sybilAtomicMTPCircuitInputs{
		IssuerClaim:           s.IssuerClaim.Claim,
		IssuerClaimMtp:        CircomSiblings(s.IssuerClaim.IncProof.Proof, s.GetMTLevel()),
		IssuerClaimClaimsRoot: s.IssuerClaim.IncProof.TreeState.ClaimsRoot,
		IssuerClaimRevRoot:    s.IssuerClaim.IncProof.TreeState.RevocationRoot,
		IssuerClaimRootsRoot:  s.IssuerClaim.IncProof.TreeState.RootOfRoots,
		IssuerClaimIdenState:  s.IssuerClaim.IncProof.TreeState.State,

		IssuerClaimNonRevMtp: CircomSiblings(s.IssuerClaim.NonRevProof.Proof, s.GetMTLevel()),

		IssuerClaimNonRevClaimsRoot: s.IssuerClaim.NonRevProof.TreeState.ClaimsRoot,
		IssuerClaimNonRevRevRoot:    s.IssuerClaim.NonRevProof.TreeState.RevocationRoot,
		IssuerClaimNonRevRootsRoot:  s.IssuerClaim.NonRevProof.TreeState.RootOfRoots,
		IssuerClaimNonRevState:      s.IssuerClaim.NonRevProof.TreeState.State,

		ClaimSchema: s.IssuerClaim.Claim.GetSchemaHash().BigInt().String(),

		StateCommitmentClaim:           s.StateCommitmentClaim.Claim,
		StateCommitmentClaimMtp:        CircomSiblings(s.StateCommitmentClaim.IncProof.Proof, s.GetMTLevel()),
		StateCommitmentClaimClaimsRoot: s.StateCommitmentClaim.IncProof.TreeState.ClaimsRoot,
		StateCommitmentClaimRevRoot:    s.StateCommitmentClaim.IncProof.TreeState.RevocationRoot,
		StateCommitmentClaimRootsRoot:  s.StateCommitmentClaim.IncProof.TreeState.RootOfRoots,
		StateCommitmentClaimIdenState:  s.StateCommitmentClaim.IncProof.TreeState.State,

		GistRoot: s.GISTProof.Root,
		GistMtp: merkletree.CircomSiblingsFromSiblings(s.GISTProof.Proof.AllSiblings(),
			s.GetMTLevelOnChain()-1),

		CRS: s.CRS,

		UserGenesisID:            s.ID.BigInt().String(),
		ProfileNonce:             s.ProfileNonce.String(),
		ClaimSubjectProfileNonce: s.ClaimSubjectProfileNonce.String(),
	}
	nodeAuxAuth := GetNodeAuxValue(s.IssuerClaim.NonRevProof.Proof)
	mtpInputs.IssuerClaimNonRevMtpNoAux = nodeAuxAuth.noAux
	mtpInputs.IssuerClaimNonRevMtpAuxHi = nodeAuxAuth.key
	mtpInputs.IssuerClaimNonRevMtpAuxHv = nodeAuxAuth.value

	gistNodeAux := GetNodeAuxValue(s.GISTProof.Proof)
	mtpInputs.GistMtpAuxHi = gistNodeAux.key
	mtpInputs.GistMtpAuxHv = gistNodeAux.value
	mtpInputs.GistMtpNoAux = gistNodeAux.noAux

	mtpInputs.RequestID = s.RequestID
	mtpInputs.IssuerID = s.IssuerClaim.IssuerID.BigInt().String()
	mtpInputs.Timestamp = s.Timestamp

	return json.Marshal(mtpInputs)
}

type SybilAtomicMTPPubSignals struct {
	BaseConfig

	SybilID *big.Int `json:"sybilID"`
	UserID  *core.ID `json:"userID"`

	RequestID *big.Int `json:"requestID"`
	IssuerID  *core.ID `json:"issuerID"`
	Timestamp int64    `json:"timestamp"`

	IssuerClaimIdenState   *merkletree.Hash `json:"issuerClaimIdenState"`
	IssuerClaimNonRevState *merkletree.Hash `json:"issuerClaimNonRevState"`
	ClaimSchema            core.SchemaHash  `json:"claimSchema"`

	CRS *big.Int `json:"crs"`

	GISTRoot *merkletree.Hash `json:"gistRoot"`
}

func (s *SybilAtomicMTPPubSignals) PubSignalsUnmarshal(data []byte) error {
	var sVals []string
	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	if len(sVals) != 10 {
		return fmt.Errorf("invalid number of Output values expected {%d} got {%d} ", 10, len(sVals))
	}

	// expected order:
	fieldIdx := 0

	//userID
	if s.UserID, err = idFromIntStr(sVals[fieldIdx]); err != nil {
		return fmt.Errorf("invalid UserID value: '%s'", sVals[fieldIdx])
	}
	fieldIdx++

	//sybilID
	var ok bool
	if s.SybilID, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid SybilID value: '%s'", sVals[fieldIdx])
	}
	fieldIdx++

	//issuerClaimIdenState
	if s.IssuerClaimIdenState, err = merkletree.NewHashFromString(sVals[fieldIdx]); err != nil {
		return fmt.Errorf("invalid IssuerClaimIdenState value: '%s'", sVals[fieldIdx])
	}
	fieldIdx++

	//issuerClaimNonRevState
	if s.IssuerClaimNonRevState, err = merkletree.NewHashFromString(sVals[fieldIdx]); err != nil {
		return fmt.Errorf("invalid IssuerClaimNonRevState value: '%s'", sVals[fieldIdx])
	}
	fieldIdx++

	//claimSchema
	var schemaInt *big.Int
	if schemaInt, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid schema value: '%s'", sVals[fieldIdx])
	}
	s.ClaimSchema = core.NewSchemaHashFromInt(schemaInt)
	fieldIdx++

	//gistRoot
	if s.GISTRoot, err = merkletree.NewHashFromString(sVals[fieldIdx]); err != nil {
		return fmt.Errorf("invalid GISTRoot value: '%s'", sVals[fieldIdx])
	}
	fieldIdx++

	//crs
	if s.CRS, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid CRS value: '%s'", sVals[fieldIdx])
	}
	fieldIdx++

	//requestID
	if s.RequestID, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid requestID value: '%s'", sVals[fieldIdx])
	}
	fieldIdx++

	//issuerID
	if s.IssuerID, err = idFromIntStr(sVals[fieldIdx]); err != nil {
		return fmt.Errorf("invalid IssuerID value: '%s'", sVals[fieldIdx])
	}
	fieldIdx++

	//timestamp
	s.Timestamp, err = strconv.ParseInt(sVals[fieldIdx], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid Timestamp value: '%s'", sVals[fieldIdx])
	}

	return nil
}

func (s SybilAtomicMTPPubSignals) GetObjMap() map[string]interface{} {
	return toMap(s)
}
