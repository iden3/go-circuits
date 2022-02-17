package circuits

import (
	"errors"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-merkletree-sql"
	"math/big"
	"strconv"
)

const (
	// AtomicQueryMTPPublicSignalsSchema is schema to parse json data for additional information
	//todo add data
	AtomicQueryMTPWithRelayPublicSignalsSchema PublicSchemaJSON = ``

	// AtomicQueryMTPVerificationKey is verification key to verify credentialAtomicQuery.circom
	//todo add data
	AtomicQueryMTPWithRelayVerificationKey VerificationKeyJSON = ``
)

type AtomicQueryMTPWithRelay struct{}

// AtomicQueryMTPInputs represents input data for kyc and kycBySignatures circuits
type AtomicQueryMTPWithRelayInputs struct {
	// auth
	ID                 *core.ID
	AuthClaim          Claim
	AuthClaimRevStatus RevocationStatus
	Challenge          int64
	Signature          *babyjub.Signature

	CurrentStateTree TreeState

	// relay
	UserStateInRelayClaim Claim

	// claim
	Claim
	RevocationStatus

	// query
	Query

	TypedInputs
}

// nolint // common approach to register default supported circuit
func init() {
	RegisterCircuit(AtomicQueryMTPWithRelayCircuitID, &AtomicQueryMTPWithRelay{})
}

func (c *AtomicQueryMTPWithRelay) PrepareInputs(in TypedInputs) (map[string]interface{}, error) {
	atomicInput, ok := in.(AtomicQueryMTPWithRelayInputs)
	if !ok {
		return nil, errors.New("wrong type of input arguments %T")
	}

	claimInputs, err := c.prepareRegularClaimInputs(atomicInput.Claim, atomicInput.RevocationStatus)
	if err != nil {
		return nil, err
	}

	authClaimInputs, err := c.prepareAuthClaimInputs(&atomicInput)
	if err != nil {
		return nil, err
	}

	queryInputs, err := c.prepareQueryInputs(&atomicInput)
	if err != nil {
		return nil, err
	}

	relayInputs, err := c.prepareRelayClaimInputs(atomicInput.UserStateInRelayClaim)

	return mergeMaps(claimInputs, authClaimInputs, queryInputs, relayInputs), nil
}

// PrepareRegularClaimInputs prepares inputs for regular claims
// todo this method violates DRY
func (c *AtomicQueryMTPWithRelay) prepareRegularClaimInputs(claim Claim, rs RevocationStatus) (map[string]interface{}, error) {

	inputs := map[string]interface{}{
		"claim": bigIntArrayToStringArray(claim.Slots),
		"claimIssuanceMtp": bigIntArrayToStringArray(
			PrepareSiblings(claim.Proof.Siblings, LevelsAtomicQueryMTPCircuit)),
		"claimIssuanceClaimsTreeRoot": claim.TreeState.
			ClaimsRootStr(),
		"claimIssuanceRevTreeRoot": claim.TreeState.
			RevocationRootStr(),
		"claimIssuanceRootsTreeRoot": claim.TreeState.
			RootOfRootsRootStr(),
		"claimIssuanceIdenState": claim.TreeState.StateStr(),
		"issuerID":               claim.IssuerID.BigInt().String(),
	}

	// revocation
	inputs["claimNonRevIssuerState"] = rs.TreeState.StateStr()
	inputs["claimNonRevIssuerRootsTreeRoot"] = rs.TreeState.
		RootOfRootsRootStr()
	inputs["claimNonRevIssuerRevTreeRoot"] = rs.TreeState.
		RevocationRootStr()
	inputs["claimNonRevIssuerClaimsTreeRoot"] = rs.TreeState.
		ClaimsRootStr()

	// claim non revocation

	inputs["claimNonRevMtp"] = bigIntArrayToStringArray(PrepareSiblings(rs.Proof.Siblings, LevelsAtomicQueryMTPCircuit))

	if rs.Proof.NodeAux == nil {
		inputs["claimNonRevMtpAuxHi"] = merkletree.HashZero.BigInt().String()
		inputs["claimNonRevMtpAuxHv"] = merkletree.HashZero.BigInt().String()
		inputs["claimNonRevMtpNoAux"] = new(big.Int).SetInt64(1).String() // (yes it's isOld = 1)
	} else {
		inputs["claimNonRevMtpNoAux"] = new(big.Int).SetInt64(0).String() // (no it's isOld = 0)
		if rs.Proof.NodeAux.HIndex == nil {
			inputs["claimNonRevMtpAuxHi"] = merkletree.HashZero.BigInt().String()
		} else {
			inputs["claimNonRevMtpAuxHi"] = rs.Proof.NodeAux.HIndex.BigInt().String()
		}
		if rs.Proof.NodeAux.HValue == nil {
			inputs["claimNonRevMtpAuxHv"] = merkletree.HashZero.BigInt().String()
		} else {
			inputs["claimNonRevMtpAuxHv"] = rs.Proof.NodeAux.HValue.BigInt().String()
		}
	}

	inputs["claimSchema"] = new(big.Int).SetBytes(claim.Schema[:]).String()
	inputs["timestamp"] = new(big.Int).SetInt64(claim.CurrentTimeStamp).String()

	return inputs, nil
}

// PrepareAuthClaimInputs prepare inputs for authorization (ID ownership)
// todo this method violated DRY except that it does not setup hoIdenState input, and has a bit different type for input param
func (c *AtomicQueryMTPWithRelay) prepareAuthClaimInputs(in *AtomicQueryMTPWithRelayInputs) (map[string]interface{}, error) {

	if in.Signature == nil {
		return nil, errors.New("signature is null")
	}

	inputs := make(map[string]interface{})
	inputs["id"] = in.ID.BigInt().String()
	inputs["challenge"] = strconv.FormatInt(in.Challenge, 10)

	inputs["authClaim"] = bigIntArrayToStringArray(in.AuthClaim.Slots)
	inputs["authClaimMtp"] = bigIntArrayToStringArray(
		PrepareSiblings(in.AuthClaim.Proof.Siblings, LevelsAtomicQueryMTPCircuit))

	inputs["hoClaimsTreeRoot"] = in.CurrentStateTree.ClaimsRootStr()
	inputs["hoRevTreeRoot"] = in.CurrentStateTree.RevocationRootStr()
	inputs["hoRootsTreeRoot"] = in.CurrentStateTree.RootOfRootsRootStr()

	inputs["authClaimNonRevMtp"] = bigIntArrayToStringArray(PrepareSiblings(in.AuthClaimRevStatus.Proof.Siblings, LevelsAtomicQueryMTPCircuit))

	if in.AuthClaimRevStatus.Proof.NodeAux == nil {
		inputs["authClaimNonRevMtpAuxHv"] = merkletree.HashZero.BigInt().String()
		inputs["authClaimNonRevMtpAuxHi"] = merkletree.HashZero.BigInt().String()
		inputs["authClaimNonRevMtpNoAux"] = new(big.Int).SetInt64(1).String() // (yes it's isOld = 1)
	} else {
		inputs["authClaimNonRevMtpNoAux"] = new(big.Int).SetInt64(0).String() // (no it's isOld = 0)
		if in.AuthClaimRevStatus.Proof.NodeAux.HIndex == nil {
			inputs["authClaimNonRevMtpAuxHi"] = merkletree.HashZero.BigInt().String()
		} else {
			inputs["authClaimNonRevMtpAuxHi"] = in.AuthClaimRevStatus.Proof.NodeAux.HIndex.BigInt().String()
		}
		if in.AuthClaimRevStatus.Proof.NodeAux.HValue == nil {
			inputs["authClaimNonRevMtpAuxHv"] = merkletree.HashZero.BigInt().String()
		} else {
			inputs["authClaimNonRevMtpAuxHv"] = in.AuthClaimRevStatus.Proof.NodeAux.HValue.BigInt().String()
		}
	}

	inputs["challengeSignatureR8x"] = in.Signature.R8.X.String()
	inputs["challengeSignatureR8y"] = in.Signature.R8.Y.String()
	inputs["challengeSignatureS"] = in.Signature.S.String()

	return inputs, nil
}

// todo this method violates DRY except that it has a bit different type for input param
func (c *AtomicQueryMTPWithRelay) prepareQueryInputs(in *AtomicQueryMTPWithRelayInputs) (map[string]interface{}, error) {
	inputs := make(map[string]interface{})
	inputs["slotIndex"] = in.Query.SlotIndex
	values, err := PrepareCircuitArrayValues(in.Query.Values, ValueArraySizeAtomicQueryMTPCircuit)
	if err != nil {
		return nil, err
	}
	inputs["value"] = bigIntArrayToStringArray(values)
	inputs["operator"] = in.Query.Operator

	return inputs, nil
}

// Prepares inputs for the claim that user state is in relay state
func (c *AtomicQueryMTPWithRelay) prepareRelayClaimInputs(claim Claim) (map[string]interface{}, error) {
	inputs := map[string]interface{}{
		"reIdenState": claim.TreeState.StateStr(),
		"hoStateInRelayerClaimMtp": bigIntArrayToStringArray(
			PrepareSiblings(claim.Proof.Siblings, LevelsAtomicQueryMTPCircuit)),
		"reProofValidClaimsTreeRoot": claim.TreeState.ClaimsRootStr(),
		"reProofValidRevTreeRoot":    claim.TreeState.RevocationRootStr(),
		"reProofValidRootsTreeRoot":  claim.TreeState.RootOfRootsRootStr(),
	}
	return inputs, nil
}

// GetVerificationKey returns verification key for circuit
func (c *AtomicQueryMTPWithRelay) GetVerificationKey() VerificationKeyJSON {
	return AtomicQueryMTPWithRelayVerificationKey
}

// GetPublicSignalsSchema returns schema to parse public inputs
func (c AtomicQueryMTPWithRelay) GetPublicSignalsSchema() PublicSchemaJSON {
	return AtomicQueryMTPWithRelayPublicSignalsSchema
}
