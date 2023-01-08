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

type SybilSigInputs struct {
	BaseConfig

	ID                       *core.ID
	ProfileNonce             *big.Int
	ClaimSubjectProfileNonce *big.Int

	IssuerClaim          ClaimWithSigProof
	StateCommitmentClaim ClaimWithMTPProof

	GISTProof GISTProof
	CRS       *big.Int

	RequestID *big.Int
	Timestamp int64
}

type sybilSigCircuitInputs struct {
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

	IssuerClaimSchema string `json:"issuerClaimSchema"`

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

	// user data
	UserGenesisID            string `json:"userGenesisID"`
	ProfileNonce             string `json:"profileNonce"`
	ClaimSubjectProfileNonce string `json:"claimSubjectProfileNonce"`

	RequestID *big.Int `json:"requestID"`
	IssuerID  string   `json:"issuerID"`
	Timestamp int64    `json:"timestamp"`
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

	if s.StateCommitmentClaim.Claim == nil {
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
		IssuerClaimSignatureR8Y: s.IssuerClaim.SignatureProof.Signature.R8.Y.String(),
		IssuerClaimSignatureS:   s.IssuerClaim.SignatureProof.Signature.S.String(),

		IssuerClaim: s.IssuerClaim.Claim,

		IssuerClaimNonRevMtp: CircomSiblings(s.IssuerClaim.NonRevProof.Proof, s.GetMTLevel()),

		IssuerClaimNonRevClaimsRoot: s.IssuerClaim.NonRevProof.TreeState.ClaimsRoot,
		IssuerClaimNonRevRevRoot:    s.IssuerClaim.NonRevProof.TreeState.RevocationRoot,
		IssuerClaimNonRevRootsRoot:  s.IssuerClaim.NonRevProof.TreeState.RootOfRoots,
		IssuerClaimNonRevState:      s.IssuerClaim.NonRevProof.TreeState.State,

		IssuerClaimSchema: s.IssuerClaim.Claim.GetSchemaHash().BigInt().String(),

		StateCommitmentClaim:           s.StateCommitmentClaim.Claim,
		StateCommitmentClaimMtp:        CircomSiblings(s.StateCommitmentClaim.IncProof.Proof, s.GetMTLevel()),
		StateCommitmentClaimClaimsRoot: s.StateCommitmentClaim.IncProof.TreeState.ClaimsRoot,
		StateCommitmentClaimRevRoot:    s.StateCommitmentClaim.IncProof.TreeState.RevocationRoot,
		StateCommitmentClaimRootsRoot:  s.StateCommitmentClaim.IncProof.TreeState.RootOfRoots,
		StateCommitmentClaimIdenState:  s.StateCommitmentClaim.IncProof.TreeState.State,

		GistRoot: s.GISTProof.Root,
		GistMtp:  CircomSiblings(s.GISTProof.Proof, s.GetMTLevel()),

		CRS: s.CRS,

		UserGenesisID:            s.ID.BigInt().String(),
		ProfileNonce:             s.ProfileNonce.String(),
		ClaimSubjectProfileNonce: s.ClaimSubjectProfileNonce.String(),
	}
	nodeAuxAuth := GetNodeAuxValue(s.IssuerClaim.NonRevProof.Proof)
	sigInputs.IssuerClaimNonRevMtpNoAux = nodeAuxAuth.noAux
	sigInputs.IssuerClaimNonRevMtpAuxHi = nodeAuxAuth.key
	sigInputs.IssuerClaimNonRevMtpAuxHv = nodeAuxAuth.value

	globalNodeAux := GetNodeAuxValue(s.GISTProof.Proof)
	sigInputs.GistMtpAuxHi = globalNodeAux.key
	sigInputs.GistMtpAuxHv = globalNodeAux.value
	sigInputs.GistMtpNoAux = globalNodeAux.noAux

	issuerAuthAux := GetNodeAuxValue(s.IssuerClaim.SignatureProof.IssuerAuthNonRevProof.Proof)
	sigInputs.IssuerAuthClaimNonRevMtpNoAux = issuerAuthAux.noAux
	sigInputs.IssuerAuthClaimNonRevMtpAuxHi = issuerAuthAux.key
	sigInputs.IssuerAuthClaimNonRevMtpAuxHv = issuerAuthAux.value

	sigInputs.RequestID = s.RequestID
	sigInputs.IssuerID = s.IssuerClaim.IssuerID.BigInt().String()
	sigInputs.Timestamp = s.Timestamp

	return json.Marshal(sigInputs)
}

type SybilSigPubSignals struct {
	BaseConfig

	SybilID *big.Int `json:"sybilID"`
	UserID  *core.ID `json:"userID"`

	RequestID *big.Int `json:"requestID"`
	IssuerID  *core.ID `json:"issuerID"`
	Timestamp int64    `json:"timestamp"`

	IssuerClaimNonRevState *merkletree.Hash `json:"issuerClaimNonRevState"`

	IssuerClaimSchema core.SchemaHash `json:"issuerClaimSchema"`

	CRS *big.Int `json:"crs"`

	GISTRoot *merkletree.Hash `json:"gistRoot"`

	IssuerAuthState *merkletree.Hash `json:"issuerAuthState"`
}

func (s *SybilSigPubSignals) PubSignalsUnmarshal(data []byte) error {
	var sVals []string
	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	if len(sVals) != 10 {
		return fmt.Errorf("invalid number of Output values expected {%d} got {%d} ", 10, len(sVals))
	}

	// expected order:
	//	0 - userID,
	//	1 - sybilID,
	//	2 - issuerAuthState,
	//	3 - requestID,
	//	4 - issuerID,
	//	5 - timestamp,
	//	6 - issuerClaimNonRevState,
	//  7 - issuerClaimSchema
	//	8 - crs,
	//	9 - gistRoot,

	fieldIdx := 0

	if s.UserID, err = idFromIntStr(sVals[fieldIdx]); err != nil {
		return err
	}
	if err != nil {
		return fmt.Errorf("invalid UserID value: '%s'", sVals[fieldIdx])
	}

	fieldIdx++

	var ok bool
	if s.SybilID, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid SybilID value: '%s'", sVals[fieldIdx])
	}

	fieldIdx++

	if s.IssuerAuthState, err = merkletree.NewHashFromString(sVals[fieldIdx]); err != nil {
		return fmt.Errorf("invalid IssuerAuthState value: '%s'", sVals[fieldIdx])
	}

	fieldIdx++

	if s.RequestID, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid requestID value: '%s'", sVals[fieldIdx])
	}

	fieldIdx++

	if s.IssuerID, err = idFromIntStr(sVals[fieldIdx]); err != nil {
		return fmt.Errorf("invalid IssuerID value: '%s'", sVals[fieldIdx])
	}

	fieldIdx++

	s.Timestamp, err = strconv.ParseInt(sVals[fieldIdx], 10, 64)
	if err != nil {
		return fmt.Errorf("invalid Timestamp value: '%s'", sVals[fieldIdx])
	}

	fieldIdx++

	if s.IssuerClaimNonRevState, err = merkletree.NewHashFromString(sVals[fieldIdx]); err != nil {
		return fmt.Errorf("invalid IssuerClaimNonRevState value: '%s'", sVals[fieldIdx])
	}

	fieldIdx++

	var schemaInt *big.Int
	if schemaInt, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid IssuerClaimSchema value: '%s'", sVals[fieldIdx])
	}
	s.IssuerClaimSchema = core.NewSchemaHashFromInt(schemaInt)

	fieldIdx++

	if s.CRS, ok = big.NewInt(0).SetString(sVals[fieldIdx], 10); !ok {
		return fmt.Errorf("invalid CRS value: '%s'", sVals[fieldIdx])
	}

	fieldIdx++

	if s.GISTRoot, err = merkletree.NewHashFromString(sVals[fieldIdx]); err != nil {
		return fmt.Errorf("invalid GISTRoot value: '%s'", sVals[fieldIdx])
	}

	return nil
}

func (s SybilSigPubSignals) GetObjMap() map[string]interface{} {
	return toMap(s)
}
