package circuits

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"

	"github.com/fatih/structs"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql"
)

//const (
//	// AtomicQueryMTPWithRelayVerificationKey is verification key to verify credentialAtomicQuery.circom
//	AtomicQueryMTPWithRelayVerificationKey VerificationKeyJSON = ``
//)

//type AtomicQueryMTPWithRelay struct{}

// AtomicQueryMTPWithRelayInputs represents input Data for kyc and kycBySignatures Data
type AtomicQueryMTPWithRelayInputs struct {
	BaseConfig

	// auth
	ID        *core.ID
	AuthClaim Claim
	Challenge *big.Int
	Signature *babyjub.Signature

	// relay
	UserStateInRelayClaim Claim

	// claim
	Claim

	CurrentTimeStamp int64
	Schema           core.SchemaHash

	// query
	Query

	InputMarshaller
}

type atomicQueryMTPWithRelayCircuitInputs struct {
	UserAuthClaim               *core.Claim      `json:"userAuthClaim"`
	UserAuthClaimMtp            []string         `json:"userAuthClaimMtp"`
	UserAuthClaimNonRevMtp      []string         `json:"userAuthClaimNonRevMtp"`
	UserAuthClaimNonRevMtpAuxHi *merkletree.Hash `json:"userAuthClaimNonRevMtpAuxHi"`
	UserAuthClaimNonRevMtpAuxHv *merkletree.Hash `json:"userAuthClaimNonRevMtpAuxHv"`
	UserAuthClaimNonRevMtpNoAux string           `json:"userAuthClaimNonRevMtpNoAux"`
	UserClaimsTreeRoot          *merkletree.Hash `json:"userClaimsTreeRoot"`
	//UserState                   *merkletree.Hash `json:"userState"`
	UserRevTreeRoot   *merkletree.Hash `json:"userRevTreeRoot"`
	UserRootsTreeRoot *merkletree.Hash `json:"userRootsTreeRoot"`
	UserID            string           `json:"userID"`

	Challenge             string `json:"challenge"`
	ChallengeSignatureR8X string `json:"challengeSignatureR8x"`
	ChallengeSignatureR8Y string `json:"challengeSignatureR8y"`
	ChallengeSignatureS   string `json:"challengeSignatureS"`

	IssuerClaim                     *core.Claim      `json:"issuerClaim"`
	IssuerClaimClaimsTreeRoot       *merkletree.Hash `json:"issuerClaimClaimsTreeRoot"`
	IssuerClaimIdenState            *merkletree.Hash `json:"issuerClaimIdenState"`
	IssuerClaimMtp                  []string         `json:"issuerClaimMtp"`
	IssuerClaimRevTreeRoot          *merkletree.Hash `json:"issuerClaimRevTreeRoot"`
	IssuerClaimRootsTreeRoot        *merkletree.Hash `json:"issuerClaimRootsTreeRoot"`
	IssuerClaimNonRevClaimsTreeRoot *merkletree.Hash `json:"issuerClaimNonRevClaimsTreeRoot"`
	IssuerClaimNonRevRevTreeRoot    *merkletree.Hash `json:"issuerClaimNonRevRevTreeRoot"`
	IssuerClaimNonRevRootsTreeRoot  *merkletree.Hash `json:"issuerClaimNonRevRootsTreeRoot"`
	IssuerClaimNonRevState          *merkletree.Hash `json:"issuerClaimNonRevState"`
	IssuerClaimNonRevMtp            []string         `json:"issuerClaimNonRevMtp"`
	IssuerClaimNonRevMtpAuxHi       *merkletree.Hash `json:"issuerClaimNonRevMtpAuxHi"`
	IssuerClaimNonRevMtpAuxHv       *merkletree.Hash `json:"issuerClaimNonRevMtpAuxHv"`
	IssuerClaimNonRevMtpNoAux       string           `json:"issuerClaimNonRevMtpNoAux"`
	ClaimSchema                     string           `json:"claimSchema"`
	IssuerID                        string           `json:"issuerID"`
	Operator                        int              `json:"operator"`
	SlotIndex                       int              `json:"slotIndex"`
	Timestamp                       int64            `json:"timestamp,string"`
	Value                           []string         `json:"value"`

	RelayProofValidClaimsTreeRoot *merkletree.Hash `json:"relayProofValidClaimsTreeRoot"`
	RelayProofValidRevTreeRoot    *merkletree.Hash `json:"relayProofValidRevTreeRoot"`
	RelayProofValidRootsTreeRoot  *merkletree.Hash `json:"relayProofValidRootsTreeRoot"`
	RelayState                    *merkletree.Hash `json:"relayState"`
	UserStateInRelayClaim         *core.Claim      `json:"userStateInRelayClaim"`
	UserStateInRelayClaimMtp      []string         `json:"userStateInRelayClaimMtp"`
}

func (a AtomicQueryMTPWithRelayInputs) CircuitInputMarshal() ([]byte, error) {

	s := atomicQueryMTPWithRelayCircuitInputs{
		UserAuthClaim: a.AuthClaim.Claim,
		UserAuthClaimMtp: PrepareSiblingsStr(a.AuthClaim.Proof.AllSiblings(),
			a.GetMTLevel()),
		UserAuthClaimNonRevMtp: PrepareSiblingsStr(a.AuthClaim.NonRevProof.Proof.AllSiblings(),
			a.GetMTLevel()),
		Challenge:                       a.Challenge.String(),
		ChallengeSignatureR8X:           a.Signature.R8.X.String(),
		ChallengeSignatureR8Y:           a.Signature.R8.Y.String(),
		ChallengeSignatureS:             a.Signature.S.String(),
		IssuerClaim:                     a.Claim.Claim,
		IssuerClaimClaimsTreeRoot:       a.Claim.TreeState.ClaimsRoot,
		IssuerClaimIdenState:            a.Claim.TreeState.State,
		IssuerClaimMtp:                  PrepareSiblingsStr(a.Claim.Proof.AllSiblings(), a.GetMTLevel()),
		IssuerClaimRevTreeRoot:          a.Claim.TreeState.RevocationRoot,
		IssuerClaimRootsTreeRoot:        a.Claim.TreeState.RootOfRoots,
		IssuerClaimNonRevClaimsTreeRoot: a.Claim.NonRevProof.TreeState.ClaimsRoot,
		IssuerClaimNonRevRevTreeRoot:    a.Claim.NonRevProof.TreeState.RevocationRoot,
		IssuerClaimNonRevRootsTreeRoot:  a.Claim.NonRevProof.TreeState.RootOfRoots,
		IssuerClaimNonRevState:          a.Claim.NonRevProof.TreeState.State,
		IssuerClaimNonRevMtp: PrepareSiblingsStr(a.Claim.NonRevProof.Proof.AllSiblings(),
			a.GetMTLevel()),
		ClaimSchema:        new(big.Int).SetBytes(a.Schema[:]).String(),
		UserClaimsTreeRoot: a.AuthClaim.TreeState.ClaimsRoot,
		//UserState:          a.AuthClaim.TreeState.State,
		UserRevTreeRoot:   a.AuthClaim.TreeState.RevocationRoot,
		UserRootsTreeRoot: a.AuthClaim.TreeState.RootOfRoots,
		UserID:            a.ID.BigInt().String(),
		IssuerID:          a.IssuerID.BigInt().String(),
		Operator:          a.Operator,
		SlotIndex:         a.SlotIndex,
		Timestamp:         a.CurrentTimeStamp,

		RelayProofValidClaimsTreeRoot: a.UserStateInRelayClaim.TreeState.ClaimsRoot,
		RelayProofValidRevTreeRoot:    a.UserStateInRelayClaim.TreeState.RevocationRoot,
		RelayProofValidRootsTreeRoot:  a.UserStateInRelayClaim.TreeState.RootOfRoots,
		RelayState:                    a.UserStateInRelayClaim.TreeState.State,
		UserStateInRelayClaim:         a.UserStateInRelayClaim.Claim,
		UserStateInRelayClaimMtp: bigIntArrayToStringArray(
			PrepareSiblings(a.UserStateInRelayClaim.Proof.AllSiblings(), a.GetMTLevel())),
	}

	values, err := PrepareCircuitArrayValues(a.Values, a.GetValueArrSize())
	if err != nil {
		return nil, err
	}
	s.Value = bigIntArrayToStringArray(values)

	nodeAuxAuth := getNodeAuxValue(a.Claim.NonRevProof.Proof.NodeAux)
	s.UserAuthClaimNonRevMtpAuxHi = nodeAuxAuth.key
	s.UserAuthClaimNonRevMtpAuxHv = nodeAuxAuth.value
	s.UserAuthClaimNonRevMtpNoAux = nodeAuxAuth.noAux

	nodeAux := getNodeAuxValue(a.Claim.NonRevProof.Proof.NodeAux)
	s.IssuerClaimNonRevMtpAuxHi = nodeAux.key
	s.IssuerClaimNonRevMtpAuxHv = nodeAux.value
	s.IssuerClaimNonRevMtpNoAux = nodeAux.noAux

	return json.Marshal(s)
}

// nolint // common approach to register default supported circuit
func init() {
	//RegisterCircuit(AtomicQueryMTPWithRelayCircuitID, &AtomicQueryMTPWithRelayOutputs{})
}

//// GetVerificationKey returns verification key for circuit
//func (ao *AtomicQueryMTPWithRelayOutputs) GetVerificationKey() VerificationKeyJSON {
//	return AtomicQueryMTPWithRelayVerificationKey
//}

type AtomicQueryMTPWithRelayOutputs struct {
	UserID      *core.ID         `json:"userID"`
	RelayState  *merkletree.Hash `json:"relayState"`
	Challenge   *big.Int         `json:"challenge"`
	ClaimSchema core.SchemaHash  `json:"claimSchema"`
	SlotIndex   int              `json:"slotIndex"`
	Operator    int              `json:"operator"`
	Value       *big.Int         `json:"value"`
	Timestamp   int64            `json:"timestamp"`
	IssuerID    *core.ID         `json:"issuerID"`
}

func (ao *AtomicQueryMTPWithRelayOutputs) CircuitOutputUnmarshal(data []byte) error {
	var sVals []string
	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	if len(sVals) != 9 {
		return fmt.Errorf("invalid number of output values expected {%d} go {%d} ", 9, len(sVals))
	}

	if ao.UserID, err = IDFromStr(sVals[0]); err != nil {
		return err
	}

	if ao.RelayState, err = merkletree.NewHashFromString(sVals[1]); err != nil {
		return err
	}

	var ok bool
	if ao.Challenge, ok = big.NewInt(0).SetString(sVals[2], 10); !ok {
		return fmt.Errorf("invalid challenge value: '%s'", sVals[0])
	}

	if ao.ClaimSchema, err = core.NewSchemaHashFromHex(sVals[3]); err != nil {
		return err
	}

	if ao.SlotIndex, err = strconv.Atoi(sVals[4]); err != nil {
		return err
	}

	if ao.Operator, err = strconv.Atoi(sVals[5]); err != nil {
		return err
	}

	if ao.Value, ok = big.NewInt(0).SetString(sVals[6], 10); !ok {
		return fmt.Errorf("invalid challenge value: '%s'", sVals[0])
	}

	if ao.Timestamp, err = strconv.ParseInt(sVals[7], 10, 64); err != nil {
		return err
	}

	if ao.IssuerID, err = IDFromStr(sVals[8]); err != nil {
		return err
	}

	return nil
}

func (ao AtomicQueryMTPWithRelayOutputs) GetJSONObjMap() map[string]interface{} {
	return structs.Map(ao)
}
