package circuits

import (
	"encoding/json"
	"math/big"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/pkg/errors"
)

// AtomicQuerySigInputs ZK private inputs for credentialAtomicQuerySig.circom
type AtomicQuerySigV2Inputs struct {
	BaseConfig

	// auth
	ID                       *core.ID
	Nonce                    *big.Int
	ClaimSubjectProfileNonce *big.Int

	Claim ClaimWithSigProof // issuerClaim

	// query
	Query JsonLDQuery

	CurrentTimeStamp int64
}

// atomicQuerySigCircuitInputs type represents credentialAtomicQuerySig.circom private inputs required by prover
type atomicQuerySigV2CircuitInputs struct {
	// user data
	UserGenesisID            string `json:"userGenesisID"`
	Nonce                    string `json:"nonce"`
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
}

// InputsMarshal returns Circom private inputs for credentialAtomicQuerySig.circom
func (a AtomicQuerySigV2Inputs) InputsMarshal() ([]byte, error) {

	if a.Claim.NonRevProof.Proof == nil {
		return nil, errors.New(ErrorEmptyClaimNonRevProof)
	}

	if a.Claim.SignatureProof.IssuerAuthIncProof.Proof == nil {
		return nil, errors.New(ErrorEmptyIssuerAuthClaimProof)
	}

	if a.Claim.SignatureProof.IssuerAuthNonRevProof.Proof == nil {
		return nil, errors.New(ErrorEmptyIssuerAuthClaimNonRevProof)
	}

	if a.Claim.SignatureProof.Signature == nil {
		return nil, errors.New(ErrorEmptyClaimSignature)
	}

	queryPathKey, err := a.Query.Path.MtEntry()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	s := atomicQuerySigV2CircuitInputs{
		UserGenesisID:                   a.ID.BigInt().String(),
		Nonce:                           a.Nonce.String(),
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
		IssuerAuthClaimNonRevMtp: PrepareSiblingsStr(a.Claim.SignatureProof.IssuerAuthNonRevProof.Proof.
			AllSiblings(), a.GetMTLevel()),
		IssuerAuthClaimsTreeRoot: a.Claim.SignatureProof.IssuerAuthNonRevProof.TreeState.ClaimsRoot.
			BigInt().String(),
		IssuerAuthRevTreeRoot:   a.Claim.SignatureProof.IssuerAuthNonRevProof.TreeState.RevocationRoot.BigInt().String(),
		IssuerAuthRootsTreeRoot: a.Claim.SignatureProof.IssuerAuthNonRevProof.TreeState.RootOfRoots.BigInt().String(),
		ClaimSchema:             a.Claim.Claim.GetSchemaHash().BigInt().String(),

		ClaimPathMtp: PrepareSiblingsStr(a.Query.MTP.AllSiblings(),
			a.GetMTLevel()),
		ClaimPathValue: a.Query.Value.Text(10),
		Operator:       a.Query.Operator,
		Timestamp:      a.CurrentTimeStamp,
		// value in this path in merklized json-ld document

		SlotIndex: a.Query.SlotIndex,
	}

	nodeAuxNonRev := GetNodeAuxValue(a.Claim.NonRevProof.Proof)
	s.IssuerClaimNonRevMtpAuxHi = nodeAuxNonRev.key
	s.IssuerClaimNonRevMtpAuxHv = nodeAuxNonRev.value
	s.IssuerClaimNonRevMtpNoAux = nodeAuxNonRev.noAux

	nodeAuxIssuerAuthNonRev := GetNodeAuxValue(a.Claim.SignatureProof.IssuerAuthNonRevProof.Proof)
	s.IssuerAuthClaimNonRevMtpAuxHi = nodeAuxIssuerAuthNonRev.key
	s.IssuerAuthClaimNonRevMtpAuxHv = nodeAuxIssuerAuthNonRev.value
	s.IssuerAuthClaimNonRevMtpNoAux = nodeAuxIssuerAuthNonRev.noAux

	s.ClaimPathNotExists = boolToInt(a.Query.MTP.Existence)
	nodAuxJSONLD := GetNodeAuxValue(a.Query.MTP)
	s.ClaimPathMtpNoAux = nodAuxJSONLD.noAux
	s.ClaimPathMtpAuxHi = nodAuxJSONLD.key
	s.ClaimPathMtpAuxHv = nodAuxJSONLD.value

	s.ClaimPathKey = queryPathKey.String()

	values, err := PrepareCircuitArrayValues(a.Query.Values, a.GetValueArrSize())
	if err != nil {
		return nil, err
	}
	s.Value = bigIntArrayToStringArray(values)

	return json.Marshal(s)
}

// AtomicQuerySigV2PubSignals public inputs
type AtomicQuerySigV2PubSignals struct {
	BaseConfig
	UserID                 string   `json:"userID"`
	IssuerID               string   `json:"issuerID"`
	IssuerAuthState        string   `json:"issuerAuthState"`
	IssuerClaimNonRevState string   `json:"issuerClaimNonRevState"`
	ClaimSchema            string   `json:"claimSchema"`
	SlotIndex              string   `json:"slotIndex"`
	Operator               int      `json:"operator"`
	Value                  []string `json:"value"`
	Timestamp              string   `json:"timestamp"`
	Merklized              string   `json:"merklized"`
	ClaimPathNotExists     string   `json:"claimPathNotExists"` // 0 for inclusion, 1 for non-inclusion
}

// PubSignalsUnmarshal unmarshal credentialAtomicQuerySig.circom public signals
func (ao *AtomicQuerySigV2PubSignals) PubSignalsUnmarshal(data []byte) error {
	// 10 is a number of fields in AtomicQuerySigV2PubSignals before values, values is last element in the proof and
	// it is length could be different base on the circuit configuration. The length could be modified by set value
	// in ValueArraySize
	//const fieldLength = 10
	//
	//var sVals []string
	//err := json.Unmarshal(data, &sVals)
	//if err != nil {
	//	return err
	//}
	//
	//if len(sVals) != fieldLength+ao.GetValueArrSize() {
	//	return fmt.Errorf("invalid number of Output values expected {%d} go {%d} ", fieldLength+ao.GetValueArrSize(), len(sVals))
	//}
	//
	//if ao.IssuerAuthState, err = merkletree.NewHashFromString(sVals[0]); err != nil {
	//	return err
	//}
	//
	//if ao.UserID, err = idFromIntStr(sVals[1]); err != nil {
	//	return err
	//}
	//
	//if ao.UserState, err = merkletree.NewHashFromString(sVals[2]); err != nil {
	//	return err
	//}
	//
	//var ok bool
	//if ao.Challenge, ok = big.NewInt(0).SetString(sVals[3], 10); !ok {
	//	return fmt.Errorf("invalid challenge value: '%s'", sVals[0])
	//}
	//
	//if ao.IssuerID, err = idFromIntStr(sVals[4]); err != nil {
	//	return err
	//}
	//
	//if ao.IssuerClaimNonRevState, err = merkletree.NewHashFromString(sVals[5]); err != nil {
	//	return err
	//}
	//
	//if ao.Timestamp, err = strconv.ParseInt(sVals[6], 10, 64); err != nil {
	//	return err
	//}
	//
	//var schemaInt *big.Int
	//if schemaInt, ok = big.NewInt(0).SetString(sVals[7], 10); !ok {
	//	return fmt.Errorf("invalid schema value: '%s'", sVals[3])
	//}
	//ao.ClaimSchema = core.NewSchemaHashFromInt(schemaInt)
	//
	//if ao.SlotIndex, err = strconv.Atoi(sVals[8]); err != nil {
	//	return err
	//}
	//
	//if ao.Operator, err = strconv.Atoi(sVals[9]); err != nil {
	//	return err
	//}
	//
	//for i, v := range sVals[fieldLength : fieldLength+ao.GetValueArrSize()] {
	//	bi, ok := big.NewInt(0).SetString(v, 10)
	//	if !ok {
	//		return fmt.Errorf("invalid value in index: %d", i)
	//	}
	//	ao.Values = append(ao.Values, bi)
	//}

	return nil
}

// GetObjMap returns struct field as a map
func (ao AtomicQuerySigV2PubSignals) GetObjMap() map[string]interface{} {
	return toMap(ao)
}
