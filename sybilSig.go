package circuits

import (
	"encoding/json"
	"fmt"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/pkg/errors"
	"math/big"
)

type SybilSigInputs struct {
	BaseConfig

	ID                       *core.ID `json:"issuerClaim"`
	ProfileNonce             *big.Int `json:"profileNonce"`
	ClaimSubjectProfileNonce *big.Int `json:"claimSubjectProfileNonce"`

	UniClaim         ClaimWithSigProof `json:"uniClaim"`
	StateSecretClaim ClaimWithMTPProof `json:"stateSecretClaim"`

	GISTProof GISTProof `json:"gistProof"`
	CRS       string    `json:"crs"`
}

type sybilSigCircuitInputs struct {

	// claim of uniqueness
	IssuerAuthClaim      *core.Claim        `json:"issuerAuthClaim"`
	IssuerAuthClaimMtp   []*merkletree.Hash `json:"issuerAuthClaimMtp"`
	IssuerAuthClaimsRoot *merkletree.Hash   `json:"issuerAuthClaimsRoot"`
	IssuerAuthRevRoot    *merkletree.Hash   `json:"issuerAuthRevRoot"`
	IssuerAuthRootsRoot  *merkletree.Hash   `json:"issuerAuthRootsRoot"`

	IssuerAuthClaimNonRevMtp      []*merkletree.Hash `json:"issuerAuthClaimNonRevMtp"`
	IssuerAuthClaimNonRevMtpAuxHi *merkletree.Hash   `json:"issuerAuthClaimNonRevMtpAuxHi"`
	IssuerAuthClaimNonRevMtpAuxHv *merkletree.Hash   `json:"issuerAuthClaimNonRevMtpAuxHv"`
	IssuerAuthClaimNonRevMtpNoAux string             `json:"issuerAuthClaimNonRevMtpNoAux"`

	IssuerClaim                 *core.Claim      `json:"issuerClaim"`
	IssuerClaimNonRevClaimsRoot *merkletree.Hash `json:"issuerClaimNonRevClaimsRoot"`
	IssuerClaimNonRevRevRoot    *merkletree.Hash `json:"issuerClaimNonRevRevRoot"`
	IssuerClaimNonRevRootsRoot  *merkletree.Hash `json:"issuerClaimNonRevRootsRoot"`

	IssuerClaimNonRevState    *merkletree.Hash   `json:"issuerClaimNonRevState"`
	IssuerClaimNonRevMtp      []*merkletree.Hash `json:"issuerClaimNonRevMtp"`
	IssuerClaimNonRevMtpAuxHi *merkletree.Hash   `json:"issuerClaimNonRevMtpAuxHi"`
	IssuerClaimNonRevMtpAuxHv *merkletree.Hash   `json:"issuerClaimNonRevMtpAuxHv"`
	IssuerClaimNonRevMtpNoAux string             `json:"issuerClaimNonRevMtpNoAux"`

	IssuerClaimSignatureR8X string `json:"issuerClaimSignatureR8x"`
	IssuerClaimSignatureR8Y string `json:"issuerClaimSignatureR8y"`
	IssuerClaimSignatureS   string `json:"issuerClaimSignatureS"`

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

func (s SybilSigInputs) Validate() error {
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

func (s SybilSigInputs) InputsMarshal() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}

	sigInputs := sybilSigCircuitInputs{
		IssuerAuthClaim: s.UniClaim.SignatureProof.IssuerAuthClaim,
		IssuerAuthClaimMtp: CircomSiblings(s.UniClaim.SignatureProof.IssuerAuthIncProof.Proof,
			s.GetMTLevel()),
		IssuerAuthClaimNonRevMtp: CircomSiblings(s.UniClaim.SignatureProof.IssuerAuthNonRevProof.Proof,
			s.GetMTLevel()),

		IssuerAuthRevRoot:    s.UniClaim.SignatureProof.IssuerAuthIncProof.TreeState.RevocationRoot,
		IssuerAuthClaimsRoot: s.UniClaim.SignatureProof.IssuerAuthIncProof.TreeState.ClaimsRoot,
		IssuerAuthRootsRoot:  s.UniClaim.SignatureProof.IssuerAuthIncProof.TreeState.RootOfRoots,

		IssuerClaimSignatureR8X: s.UniClaim.SignatureProof.Signature.R8.X.String(),
		IssuerClaimSignatureR8Y: s.UniClaim.SignatureProof.Signature.R8.X.String(),
		IssuerClaimSignatureS:   s.UniClaim.SignatureProof.Signature.R8.X.String(),

		IssuerClaim: s.UniClaim.Claim,

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
	sigInputs.IssuerClaimNonRevMtpNoAux = uniAux.noAux
	sigInputs.IssuerClaimNonRevMtpAuxHi = uniAux.key
	sigInputs.IssuerClaimNonRevMtpAuxHv = uniAux.value

	gistAux := GetNodeAuxValue(s.GISTProof.Proof)
	sigInputs.GistMtpAuxHi = gistAux.key
	sigInputs.GistMtpAuxHv = gistAux.value
	sigInputs.GistMtpNoAux = gistAux.noAux

	issuerAuthAux := GetNodeAuxValue(s.UniClaim.SignatureProof.IssuerAuthNonRevProof.Proof)
	sigInputs.IssuerAuthClaimNonRevMtpNoAux = issuerAuthAux.noAux
	sigInputs.IssuerAuthClaimNonRevMtpAuxHi = issuerAuthAux.key
	sigInputs.IssuerAuthClaimNonRevMtpAuxHv = issuerAuthAux.value

	return json.Marshal(sigInputs)

}

type SybilSigPubSignals struct {
	BaseConfig

	IssuerClaimNonRevState *merkletree.Hash `json:"issuerClaimNonRevState"`

	GISTRoot *merkletree.Hash `json:"gistRoot"`
	CRS      string           `json:"crs"`
}

func (s *SybilSigPubSignals) PubSignalsUnmarshal(data []byte) error {
	var sVals []string
	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	if len(sVals) != 3 {
		return fmt.Errorf("invalid number of Output values expected {%d} got {%d} ", 3, len(sVals))
	}

	// expected order:
	//	0 - issuerClaimNonRevState,
	//	1 - crs,
	//	2 - gistRoot,

	if s.IssuerClaimNonRevState, err = merkletree.NewHashFromString(sVals[0]); err != nil {
		return err
	}

	s.CRS = sVals[1]

	if s.GISTRoot, err = merkletree.NewHashFromString(sVals[2]); err != nil {
		return err
	}

	return nil
}

func (s SybilSigPubSignals) GetObjMap() map[string]interface{} {
	return toMap(s)
}
