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

	ID                       *core.ID `json:"id"`
	ProfileNonce             *big.Int `json:"profileNonce"`
	ClaimSubjectProfileNonce *big.Int `json:"claimSubjectProfileNonce"`

	IssuerClaim ClaimWithSigProof `json:"issuerClaim"`
	HolderClaim ClaimWithMTPProof `json:"holderClaim"`

	GISTProof GISTProof `json:"gistProof"`
	CRS       string    `json:"crs"`

	RequestID        string `json:"requestID"`
	IssuerID         string `json:"issuerID"`
	CurrentTimestamp string `json:"currentTimestamp"`
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

	RequestID        string `json:"requestID"`
	IssuerID         string `json:"issuerID"`
	CurrentTimestamp string `json:"currentTimestamp"`
}

func (s SybilSigInputs) Validate() error {
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

func (s SybilSigInputs) InputsMarshal() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}

	sigInputs := sybilSigCircuitInputs{
		IssuerAuthClaim: s.IssuerClaim.SignatureProof.IssuerAuthClaim,
		IssuerAuthClaimMtp: CircomSiblings(s.IssuerClaim.SignatureProof.IssuerAuthIncProof.Proof,
			s.GetMTLevel()),
		IssuerAuthClaimNonRevMtp: CircomSiblings(s.IssuerClaim.SignatureProof.IssuerAuthNonRevProof.Proof,
			s.GetMTLevel()),

		IssuerAuthRevRoot:    s.IssuerClaim.SignatureProof.IssuerAuthIncProof.TreeState.RevocationRoot,
		IssuerAuthClaimsRoot: s.IssuerClaim.SignatureProof.IssuerAuthIncProof.TreeState.ClaimsRoot,
		IssuerAuthRootsRoot:  s.IssuerClaim.SignatureProof.IssuerAuthIncProof.TreeState.RootOfRoots,

		IssuerClaimSignatureR8X: s.IssuerClaim.SignatureProof.Signature.R8.X.String(),
		IssuerClaimSignatureR8Y: s.IssuerClaim.SignatureProof.Signature.R8.X.String(),
		IssuerClaimSignatureS:   s.IssuerClaim.SignatureProof.Signature.R8.X.String(),

		IssuerClaim: s.IssuerClaim.Claim,

		IssuerClaimNonRevMtp: CircomSiblings(s.IssuerClaim.NonRevProof.Proof, s.GetMTLevel()),

		IssuerClaimNonRevClaimsRoot: s.IssuerClaim.NonRevProof.TreeState.ClaimsRoot,
		IssuerClaimNonRevRevRoot:    s.IssuerClaim.NonRevProof.TreeState.RevocationRoot,
		IssuerClaimNonRevRootsRoot:  s.IssuerClaim.NonRevProof.TreeState.RootOfRoots,
		IssuerClaimNonRevState:      s.IssuerClaim.NonRevProof.TreeState.State,

		// claim of state-secret (Holder's claim)
		HolderClaim:           s.HolderClaim.Claim,
		HolderClaimMtp:        CircomSiblings(s.HolderClaim.IncProof.Proof, s.GetMTLevel()-1),
		HolderClaimClaimsRoot: s.HolderClaim.IncProof.TreeState.ClaimsRoot,
		HolderClaimRevRoot:    s.HolderClaim.IncProof.TreeState.ClaimsRoot,
		HolderClaimRootsRoot:  s.HolderClaim.IncProof.TreeState.ClaimsRoot,
		HolderClaimIdenState:  s.HolderClaim.IncProof.TreeState.ClaimsRoot,

		GistRoot: s.GISTProof.Root,
		GistMtp:  CircomSiblings(s.GISTProof.Proof, s.GetMTLevel()),

		CRS: s.CRS,

		// user data
		UserGenesisID:            s.ID.String(),
		ProfileNonce:             s.ProfileNonce.String(),
		ClaimSubjectProfileNonce: s.ClaimSubjectProfileNonce.String(),
	}
	uniAux := GetNodeAuxValue(s.IssuerClaim.NonRevProof.Proof)
	sigInputs.IssuerClaimNonRevMtpNoAux = uniAux.noAux
	sigInputs.IssuerClaimNonRevMtpAuxHi = uniAux.key
	sigInputs.IssuerClaimNonRevMtpAuxHv = uniAux.value

	gistAux := GetNodeAuxValue(s.GISTProof.Proof)
	sigInputs.GistMtpAuxHi = gistAux.key
	sigInputs.GistMtpAuxHv = gistAux.value
	sigInputs.GistMtpNoAux = gistAux.noAux

	issuerAuthAux := GetNodeAuxValue(s.IssuerClaim.SignatureProof.IssuerAuthNonRevProof.Proof)
	sigInputs.IssuerAuthClaimNonRevMtpNoAux = issuerAuthAux.noAux
	sigInputs.IssuerAuthClaimNonRevMtpAuxHi = issuerAuthAux.key
	sigInputs.IssuerAuthClaimNonRevMtpAuxHv = issuerAuthAux.value

	sigInputs.RequestID = s.RequestID
	sigInputs.IssuerID = s.IssuerID
	sigInputs.CurrentTimestamp = s.CurrentTimestamp

	return json.Marshal(sigInputs)
}

type SybilSigPubSignals struct {
	BaseConfig

	SybilID string `json:"sybilID"`
	UserID  string `json:"userID"`

	RequestID        string `json:"requestID"`
	IssuerID         string `json:"issuerID"`
	CurrentTimestamp string `json:"currentTimestamp"`

	IssuerClaimNonRevState *merkletree.Hash `json:"issuerClaimNonRevState"`

	CRS string `json:"crs"`

	GISTRoot *merkletree.Hash `json:"gistRoot"`

	IssuerAuthState *merkletree.Hash `json:"issuerAuthState"`
}

func (s *SybilSigPubSignals) PubSignalsUnmarshal(data []byte) error {
	var sVals []string
	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	if len(sVals) != 9 {
		return fmt.Errorf("invalid number of Output values expected {%d} got {%d} ", 9, len(sVals))
	}

	// expected order:
	//	0 - userID,
	//	1 - sybilID,
	//	2 - issuerAuthState,
	//	3 - requestID,
	//	4 - issuerID,
	//	5 - timestamp,
	//	6 - issuerClaimNonRevState,
	//	7 - crs,
	//	8 - gistRoot,

	s.UserID = sVals[0]
	s.SybilID = sVals[1]
	if s.IssuerAuthState, err = merkletree.NewHashFromString(sVals[2]); err != nil {
		return err
	}

	s.RequestID = sVals[3]
	s.IssuerID = sVals[4]
	s.CurrentTimestamp = sVals[5]

	if s.IssuerClaimNonRevState, err = merkletree.NewHashFromString(sVals[6]); err != nil {
		return err
	}

	s.CRS = sVals[7]

	if s.GISTRoot, err = merkletree.NewHashFromString(sVals[8]); err != nil {
		return err
	}

	return nil
}

func (s SybilSigPubSignals) GetObjMap() map[string]interface{} {
	return toMap(s)
}
