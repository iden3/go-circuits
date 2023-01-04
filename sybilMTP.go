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

type SybilMTPInputs struct {
	BaseConfig

	ID                       *core.ID `json:"id"`
	ProfileNonce             *big.Int `json:"profileNonce"`
	ClaimSubjectProfileNonce *big.Int `json:"claimSubjectProfileNonce"`

	IssuerClaim ClaimWithMTPProof `json:"issuerClaim"`
	HolderClaim ClaimWithMTPProof `json:"holderClaim"`

	GISTProof GISTProof `json:"gistProof"`
	CRS       *big.Int  `json:"crs"`

	RequestID *big.Int `json:"requestID"`
	IssuerID  *core.ID `json:"issuerID"`
	Timestamp int64    `json:"timestamp"`
}

type sybilMTPCircuitInputs struct {
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

	IssuerClaimSchema string `json:"issuerClaimSchema"`

	HolderClaim           *core.Claim        `json:"holderClaim"`
	HolderClaimMtp        []*merkletree.Hash `json:"holderClaimMtp"`
	HolderClaimClaimsRoot *merkletree.Hash   `json:"holderClaimClaimsRoot"`
	HolderClaimRevRoot    *merkletree.Hash   `json:"holderClaimRevRoot"`
	HolderClaimRootsRoot  *merkletree.Hash   `json:"holderClaimRootsRoot"`
	HolderClaimIdenState  *merkletree.Hash   `json:"holderClaimIdenState"`

	GistRoot     *merkletree.Hash   `json:"gistRoot"`
	GistMtp      []*merkletree.Hash `json:"gistMtp"`
	GistMtpAuxHi *merkletree.Hash   `json:"gistMtpAuxHi"`
	GistMtpAuxHv *merkletree.Hash   `json:"gistMtpAuxHv"`
	GistMtpNoAux string             `json:"gistMtpNoAux"`

	CRS *big.Int `json:"crs"`

	UserGenesisID            *core.ID `json:"userGenesisID"`
	ProfileNonce             string   `json:"profileNonce"`
	ClaimSubjectProfileNonce string   `json:"claimSubjectProfileNonce"`

	RequestID *big.Int `json:"requestID"`
	IssuerID  *core.ID `json:"issuerID"`
	Timestamp int64    `json:"timestamp"`
}

func (s SybilMTPInputs) Validate() error {

	if s.ID == nil {
		return errors.New(ErrorEmptyID)
	}

	if s.GISTProof.Proof == nil {
		return errors.New(ErrorEmptyGlobalProof)
	}

	if s.IssuerClaim.Claim == nil {
		return errors.New(ErrorEmptyGlobalProof)
	}

	if s.HolderClaim.Claim == nil {
		return errors.New(ErrorEmptyGlobalProof)
	}

	return nil
}

func (s SybilMTPInputs) InputsMarshal() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}

	mtpInputs := sybilMTPCircuitInputs{
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

		IssuerClaimSchema: s.IssuerClaim.Claim.GetSchemaHash().BigInt().String(),

		// claim of state-secret (Holder's claim)
		HolderClaim:           s.HolderClaim.Claim,
		HolderClaimMtp:        CircomSiblings(s.HolderClaim.IncProof.Proof, s.GetMTLevel()),
		HolderClaimClaimsRoot: s.HolderClaim.IncProof.TreeState.ClaimsRoot,
		HolderClaimRevRoot:    s.HolderClaim.IncProof.TreeState.ClaimsRoot,
		HolderClaimRootsRoot:  s.HolderClaim.IncProof.TreeState.ClaimsRoot,
		HolderClaimIdenState:  s.HolderClaim.IncProof.TreeState.ClaimsRoot,

		GistRoot: s.GISTProof.Root,
		GistMtp:  CircomSiblings(s.GISTProof.Proof, s.GetMTLevel()),

		CRS: s.CRS,

		// user data
		UserGenesisID:            s.ID,
		ProfileNonce:             s.ProfileNonce.String(),
		ClaimSubjectProfileNonce: s.ClaimSubjectProfileNonce.String(),
	}
	issuerClaimAux := GetNodeAuxValue(s.IssuerClaim.NonRevProof.Proof)
	mtpInputs.IssuerClaimNonRevMtpNoAux = issuerClaimAux.noAux
	mtpInputs.IssuerClaimNonRevMtpAuxHi = issuerClaimAux.key
	mtpInputs.IssuerClaimNonRevMtpAuxHv = issuerClaimAux.value

	gistAux := GetNodeAuxValue(s.GISTProof.Proof)
	mtpInputs.GistMtpAuxHi = gistAux.key
	mtpInputs.GistMtpAuxHv = gistAux.value
	mtpInputs.GistMtpNoAux = gistAux.noAux

	mtpInputs.RequestID = s.RequestID
	mtpInputs.IssuerID = s.IssuerID
	mtpInputs.Timestamp = s.Timestamp

	return json.Marshal(mtpInputs)
}

type SybilMTPPubSignals struct {
	BaseConfig

	SybilID *big.Int `json:"sybilID"`
	UserID  *core.ID `json:"userID"`

	RequestID *big.Int `json:"requestID"`
	IssuerID  *core.ID `json:"issuerID"`
	Timestamp int64    `json:"timestamp"`

	IssuerClaimIdenState   *merkletree.Hash `json:"issuerClaimIdenState"`
	IssuerClaimNonRevState *merkletree.Hash `json:"issuerClaimNonRevState"`
	IssuerClaimSchema      core.SchemaHash  `json:"issuerClaimSchema"`

	CRS *big.Int `json:"crs"`

	GISTRoot *merkletree.Hash `json:"gistRoot"`
}

func (s *SybilMTPPubSignals) PubSignalsUnmarshal(data []byte) error {
	var sVals []string
	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	if len(sVals) != 10 {
		return fmt.Errorf("invalid number of Output values expected {%d} got {%d} ", 10, len(sVals))
	}

	// expected order:
	//	0 - userID
	//	1 - sybilID
	//	2 - requestID
	//	3 - issuerID
	//	4 - currentTimestamp
	//	5 - issuerClaimIdenState
	//	6 - issuerClaimNonRevState
	//  7 - issuerClaimSchema
	//  8 - crs
	//  9 - gistRoot

	if s.UserID, err = idFromIntStr(sVals[0]); err != nil {
		return fmt.Errorf("invalid UserID value: '%s'", sVals[0])
	}

	var ok bool
	if s.SybilID, ok = big.NewInt(0).SetString(sVals[1], 10); !ok {
		return fmt.Errorf("invalid SybilID value: '%s'", sVals[1])
	}

	if s.RequestID, ok = big.NewInt(0).SetString(sVals[2], 10); !ok {
		return fmt.Errorf("invalid requestID value: '%s'", sVals[2])
	}

	if s.IssuerID, err = idFromIntStr(sVals[3]); err != nil {
		return err
	}

	s.Timestamp, err = strconv.ParseInt(sVals[4], 10, 64)
	if err != nil {
		return err
	}

	if s.IssuerClaimIdenState, err = merkletree.NewHashFromString(sVals[5]); err != nil {
		return err
	}
	if s.IssuerClaimNonRevState, err = merkletree.NewHashFromString(sVals[6]); err != nil {
		return err
	}

	var schemaInt *big.Int
	if schemaInt, ok = big.NewInt(0).SetString(sVals[7], 10); !ok {
		return fmt.Errorf("invalid schema value: '%s'", sVals[7])
	}
	s.IssuerClaimSchema = core.NewSchemaHashFromInt(schemaInt)

	if s.CRS, ok = big.NewInt(0).SetString(sVals[8], 10); !ok {
		return fmt.Errorf("invalid CRS value: '%s'", sVals[2])
	}

	if s.GISTRoot, err = merkletree.NewHashFromString(sVals[9]); err != nil {
		return err
	}

	return nil
}

func (s SybilMTPPubSignals) GetObjMap() map[string]interface{} {
	return toMap(s)
}
