package circuits

import (
	"encoding/json"
	"fmt"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/pkg/errors"
	"math/big"
)

type SybilMTPInputs struct {
	BaseConfig

	ID                       *core.ID `json:"issuerClaim"`
	ProfileNonce             *big.Int `json:"profileNonce"`
	ClaimSubjectProfileNonce *big.Int `json:"claimSubjectProfileNonce"`

	UniClaim         ClaimWithMTPProof `json:"uniClaim"`
	StateSecretClaim ClaimWithMTPProof `json:"stateSecretClaim"`

	GISTProof GISTProof `json:"gistProof"`
	CRS       string    `json:"crs"`
}

type sybilMTPCircuitInputs struct {
	IssuerClaim           *core.Claim        `json:"issuerClaim"`
	IssuerClaimMtp        []*merkletree.Hash `json:"issuerClaimMtp"`
	IssuerClaimClaimsRoot *merkletree.Hash   `json:"issuerClaimClaimsRoot"`
	IssuerClaimRevRoot    *merkletree.Hash   `json:"issuerClaimRevRoot"`
	IssuerClaimRootsRoot  *merkletree.Hash   `json:"issuerClaimRootsRoot"`
	IssuerClaimIdenState  *merkletree.Hash   `json:"IssuerClaimIdenState"`

	IssuerClaimNonRevMtp      []*merkletree.Hash `json:"issuerClaimNonRevMtp"`
	IssuerClaimNonRevMtpNoAux string             `json:"issuerClaimNonRevMtpNoAux"`
	IssuerClaimNonRevMtpAuxHi *merkletree.Hash   `json:"issuerClaimNonRevMtpAuxHi"`
	IssuerClaimNonRevMtpAuxHv *merkletree.Hash   `json:"issuerClaimNonRevMtpAuxHv"`

	IssuerClaimNonRevClaimsRoot *merkletree.Hash `json:"issuerClaimNonRevClaimsRoot"`
	IssuerClaimNonRevRevRoot    *merkletree.Hash `json:"issuerClaimNonRevRevRoot"`
	IssuerClaimNonRevRootsRoot  *merkletree.Hash `json:"issuerClaimNonRevRootsRoot"`
	IssuerClaimNonRevState      *merkletree.Hash `json:"IssuerClaimNonRevState"`

	// claim of state-secret (Holder's claim)
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

	CRS string `json:"crs"`

	// user data
	UserGenesisID            string `json:"userGenesisID"`
	ProfileNonce             string `json:"profileNonce"`
	ClaimSubjectProfileNonce string `json:"claimSubjectProfileNonce"`
}

func (s SybilMTPInputs) Validate() error {

	if s.ID == nil {
		return errors.New(ErrorEmptyID)
	}

	if s.GISTProof.Proof == nil {
		return errors.New(ErrorEmptyGlobalProof)
	}

	if s.UniClaim.Claim == nil {
		return errors.New(ErrorEmptyGlobalProof)
	}

	if s.StateSecretClaim.Claim == nil {
		return errors.New(ErrorEmptyGlobalProof)
	}

	return nil
}

func (s SybilMTPInputs) InputsMarshal() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}

	mtpInputs := sybilMTPCircuitInputs{
		IssuerClaim:           s.UniClaim.Claim,
		IssuerClaimMtp:        CircomSiblings(s.UniClaim.IncProof.Proof, s.GetMTLevel()-1),
		IssuerClaimClaimsRoot: s.UniClaim.IncProof.TreeState.ClaimsRoot,
		IssuerClaimRevRoot:    s.UniClaim.IncProof.TreeState.RevocationRoot,
		IssuerClaimRootsRoot:  s.UniClaim.IncProof.TreeState.RootOfRoots,
		IssuerClaimIdenState:  s.UniClaim.IncProof.TreeState.State,

		IssuerClaimNonRevMtp: CircomSiblings(s.UniClaim.NonRevProof.Proof, s.GetMTLevel()),

		IssuerClaimNonRevClaimsRoot: s.UniClaim.NonRevProof.TreeState.ClaimsRoot,
		IssuerClaimNonRevRevRoot:    s.UniClaim.NonRevProof.TreeState.RevocationRoot,
		IssuerClaimNonRevRootsRoot:  s.UniClaim.NonRevProof.TreeState.RootOfRoots,
		IssuerClaimNonRevState:      s.UniClaim.NonRevProof.TreeState.State,

		// claim of state-secret (Holder's claim)
		HolderClaim:           s.StateSecretClaim.Claim,
		HolderClaimMtp:        CircomSiblings(s.StateSecretClaim.IncProof.Proof, s.GetMTLevel()-1),
		HolderClaimClaimsRoot: s.StateSecretClaim.IncProof.TreeState.ClaimsRoot,
		HolderClaimRevRoot:    s.StateSecretClaim.IncProof.TreeState.ClaimsRoot,
		HolderClaimRootsRoot:  s.StateSecretClaim.IncProof.TreeState.ClaimsRoot,
		HolderClaimIdenState:  s.StateSecretClaim.IncProof.TreeState.ClaimsRoot,

		GistRoot: s.GISTProof.Root,
		GistMtp:  CircomSiblings(s.GISTProof.Proof, s.GetMTLevel()),

		CRS: s.CRS,

		// user data
		UserGenesisID:            s.ID.String(),
		ProfileNonce:             s.ProfileNonce.String(),
		ClaimSubjectProfileNonce: s.ClaimSubjectProfileNonce.String(),
	}
	uniAux := GetNodeAuxValue(s.UniClaim.NonRevProof.Proof)
	mtpInputs.IssuerClaimNonRevMtpNoAux = uniAux.noAux
	mtpInputs.IssuerClaimNonRevMtpAuxHi = uniAux.key
	mtpInputs.IssuerClaimNonRevMtpAuxHv = uniAux.value

	gistAux := GetNodeAuxValue(s.GISTProof.Proof)
	mtpInputs.GistMtpAuxHi = gistAux.key
	mtpInputs.GistMtpAuxHv = gistAux.value
	mtpInputs.GistMtpNoAux = gistAux.noAux

	return json.Marshal(mtpInputs)
}

type SybilMTPPubSignals struct {
	BaseConfig

	IssuerClaimIdenState   *merkletree.Hash `json:"issuerClaimIdenState"`
	IssuerClaimNonRevState *merkletree.Hash `json:"issuerClaimNonRevState"`

	GISTRoot *merkletree.Hash `json:"gistRoot"`
	CRS      string           `json:"crs"`
}

func (s *SybilMTPPubSignals) PubSignalsUnmarshal(data []byte) error {
	var sVals []string
	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	if len(sVals) != 4 {
		return fmt.Errorf("invalid number of Output values expected {%d} got {%d} ", 4, len(sVals))
	}

	// expected order:
	//	0 - IssuerClaimIdenState,
	//	1 - IssuerClaimNonRevState,
	//	2 - crs,
	//	3 - gistRoot

	if s.IssuerClaimIdenState, err = merkletree.NewHashFromString(sVals[0]); err != nil {
		return err
	}
	if s.IssuerClaimNonRevState, err = merkletree.NewHashFromString(sVals[1]); err != nil {
		return err
	}

	s.CRS = sVals[2]

	if s.GISTRoot, err = merkletree.NewHashFromString(sVals[3]); err != nil {
		return err
	}

	return nil
}

func (s SybilMTPPubSignals) GetObjMap() map[string]interface{} {
	return toMap(s)
}
