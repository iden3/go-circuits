package circuits

import (
	"context"
	"math/big"
	"testing"

	it "github.com/iden3/go-circuits/v2/testing"
	"github.com/stretchr/testify/require"
)

func TestAdjustInputsForMinCircuit_AtomicQueryV3_Sig(t *testing.T) {
	inputs := createV3Inputs_Sig(t)

	circuitID, err := AdjustInputsForMinCircuit(&inputs)
	require.NoError(t, err)
	require.Equal(t, CircuitID("credentialAtomicQueryV3-16-16-64"), circuitID)
	require.Equal(t, presetCfg16_16_64_32, inputs.BaseConfig)

	// Verify the config works with InputsMarshal
	_, err = inputs.InputsMarshal()
	require.NoError(t, err)
}

func TestAdjustInputsForMinCircuit_AtomicQueryV3_Mtp(t *testing.T) {
	inputs := createV3Inputs_Mtp(t)

	circuitID, err := AdjustInputsForMinCircuit(&inputs)
	require.NoError(t, err)
	require.Equal(t, CircuitID("credentialAtomicQueryV3-16-16-64"), circuitID)
	require.Equal(t, presetCfg16_16_64_32, inputs.BaseConfig)

	// Verify the config works with InputsMarshal
	_, err = inputs.InputsMarshal()
	require.NoError(t, err)
}

func TestAdjustInputsForMinCircuit_AtomicQueryV3_NilPointer(t *testing.T) {
	var inputs *AtomicQueryV3Inputs

	_, err := AdjustInputsForMinCircuit(inputs)
	require.Error(t, err)
	require.Contains(t, err.Error(), ErrorInputsTypeNotSupported)
}

func TestAdjustInputsForMinCircuit_AtomicQueryV3OnChain(t *testing.T) {
	inputs := createV3OnChainInputs_BJJAuth(t)

	circuitID, err := AdjustInputsForMinCircuit(&inputs)
	require.NoError(t, err)
	require.Equal(t, CircuitID("credentialAtomicQueryV3OnChain-16-16-64-16-32"), circuitID)
	require.Equal(t, presetCfg16_16_64_32, inputs.BaseConfig)

	// Verify the config works with InputsMarshal
	_, err = inputs.InputsMarshal()
	require.NoError(t, err)
}

func TestAdjustInputsForMinCircuit_AtomicQueryV3OnChain_NoBJJAuth(t *testing.T) {
	inputs := createV3OnChainInputs_NoBJJAuth(t)

	circuitID, err := AdjustInputsForMinCircuit(&inputs)
	require.NoError(t, err)
	require.Equal(t, CircuitID("credentialAtomicQueryV3OnChain-16-16-64-16-32"), circuitID)
	require.Equal(t, presetCfg16_16_64_32, inputs.BaseConfig)

	_, err = inputs.InputsMarshal()
	require.NoError(t, err)
}

func TestAdjustInputsForMinCircuit_AtomicQueryV3OnChain_NilPointer(t *testing.T) {
	var inputs *AtomicQueryV3OnChainInputs

	_, err := AdjustInputsForMinCircuit(inputs)
	require.Error(t, err)
	require.Contains(t, err.Error(), ErrorInputsTypeNotSupported)
}

func TestAdjustInputsForMinCircuit_AuthV3(t *testing.T) {
	inputs := authV3Inputs(t, false)

	circuitID, err := AdjustInputsForMinCircuit(&inputs)
	require.NoError(t, err)
	require.Equal(t, AuthV3_8_32CircuitID, circuitID)
	require.Equal(t, presetCfg8_32, inputs.BaseConfig)

	// Verify the config works with InputsMarshal
	_, err = inputs.InputsMarshal()
	require.NoError(t, err)
}

func TestAdjustInputsForMinCircuit_AuthV3_NilPointer(t *testing.T) {
	var inputs *AuthV3Inputs

	_, err := AdjustInputsForMinCircuit(inputs)
	require.Error(t, err)
	require.Contains(t, err.Error(), ErrorInputsTypeNotSupported)
}

func TestAdjustInputsForMinCircuit_SelectsSmallestCircuit(t *testing.T) {
	// With small proofs, should select the smaller circuit variant
	inputs := createV3Inputs_Sig(t)

	circuitID, err := AdjustInputsForMinCircuit(&inputs)
	require.NoError(t, err)

	// The test identity creates shallow trees, so should fit in small circuit
	require.Equal(t, CircuitID("credentialAtomicQueryV3-16-16-64"), circuitID)
	require.Equal(t, 16, inputs.MTLevel)
	require.Equal(t, 16, inputs.MTLevelClaim)
	require.Equal(t, 64, inputs.ValueArraySize)
	require.Equal(t, 32, inputs.MTLevelOnChain)
}

func TestAdjustInputsForMinCircuit_AtomicQueryV3OnChain_CircuitID(t *testing.T) {
	inputs := createV3OnChainInputs_BJJAuth(t)

	circuitID, err := AdjustInputsForMinCircuit(&inputs)
	require.NoError(t, err)
	require.Equal(t, CircuitID("credentialAtomicQueryV3OnChain-16-16-64-16-32"), circuitID)
}

func TestAdjustInputsForMinCircuit_LargeValueArray(t *testing.T) {
	inputs := createV3Inputs_Sig(t)

	// Create query with many values (but still within limit)
	inputs.Query.Values = make([]*big.Int, 60)
	for i := range inputs.Query.Values {
		inputs.Query.Values[i] = big.NewInt(int64(i))
	}

	circuitID, err := AdjustInputsForMinCircuit(&inputs)
	require.NoError(t, err)
	require.Equal(t, CircuitID("credentialAtomicQueryV3-16-16-64"), circuitID)
	require.GreaterOrEqual(t, inputs.GetValueArrSize(), 60)
}

// Test fit functions directly to verify selection logic

func TestFitsAtomicQueryV3Config(t *testing.T) {
	tests := []struct {
		name       string
		mtReq      int
		mtClaimReq int
		valueReq   int
		cfg        BaseConfig
		want       bool
	}{
		{"fits small", 10, 10, 32, presetCfg16_16_64_32, true},
		{"mt too large for small", 20, 10, 32, presetCfg16_16_64_32, false},
		{"claim too large for small", 10, 20, 32, presetCfg16_16_64_32, false},
		{"value too large for small", 10, 10, 100, presetCfg16_16_64_32, false},
		{"fits large", 30, 30, 60, presetCfg40_32_64_64, true},
		{"mt too large for large", 50, 10, 32, presetCfg40_32_64_64, false},
		{"exact boundary small", 16, 16, 64, presetCfg16_16_64_32, true},
		{"exact boundary large", 40, 32, 64, presetCfg40_32_64_64, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fitsAtomicQueryV3Config(tt.mtReq, tt.mtClaimReq, tt.valueReq, tt.cfg)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestFitsAtomicQueryV3OnChainConfig(t *testing.T) {
	tests := []struct {
		name         string
		mtReq        int
		mtClaimReq   int
		valueReq     int
		mtOnChainReq int
		cfg          BaseConfig
		want         bool
	}{
		{"fits small", 10, 10, 32, 20, presetCfg16_16_64_32, true},
		{"onchain too large for small", 10, 10, 32, 40, presetCfg16_16_64_32, false},
		{"fits large", 30, 30, 60, 50, presetCfg40_32_64_64, true},
		{"onchain too large for large", 30, 30, 60, 70, presetCfg40_32_64_64, false},
		{"exact boundary small", 16, 16, 64, 32, presetCfg16_16_64_32, true},
		{"exact boundary large", 40, 32, 64, 64, presetCfg40_32_64_64, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fitsAtomicQueryV3OnChainConfig(tt.mtReq, tt.mtClaimReq, tt.valueReq, tt.mtOnChainReq, tt.cfg)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestFitsAuthV3Config(t *testing.T) {
	tests := []struct {
		name         string
		mtReq        int
		mtOnChainReq int
		cfg          BaseConfig
		want         bool
	}{
		{"fits small", 5, 20, presetCfg8_32, true},
		{"mt too large for small", 10, 20, presetCfg8_32, false},
		{"onchain too large for small", 5, 40, presetCfg8_32, false},
		{"fits large", 30, 50, presetCfg40_32_64_64, true},
		{"mt too large for large", 50, 50, presetCfg40_32_64_64, false},
		{"onchain too large for large", 30, 70, presetCfg40_32_64_64, false},
		{"exact boundary small", 8, 32, presetCfg8_32, true},
		{"exact boundary large", 40, 64, presetCfg40_32_64_64, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fitsAuthV3Config(tt.mtReq, tt.mtOnChainReq, tt.cfg)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestProofSiblingsLen(t *testing.T) {
	require.Equal(t, 0, proofSiblingsLen(nil))

	user := it.NewIdentity(t, userPK)
	proof, _ := user.ClaimMTPRaw(t, user.AuthClaim)
	require.GreaterOrEqual(t, proofSiblingsLen(proof), 0)
}

// Helper functions

// createV3OnChainInputs_BJJAuth creates AtomicQueryV3OnChainInputs with BJJ auth enabled.
func createV3OnChainInputs_BJJAuth(t testing.TB) AtomicQueryV3OnChainInputs {
	ctx := context.Background()
	user := it.NewIdentity(t, userPK)
	issuer := it.NewIdentity(t, issuerPK)

	subjectID := user.ID
	claim := it.DefaultUserClaim(t, subjectID)

	claimSig := issuer.SignClaim(t, claim)
	issuerClaimNonRevMtp, _ := issuer.ClaimRevMTPRaw(t, claim)
	issuerAuthClaimNonRevMtp, _ := issuer.ClaimRevMTPRaw(t, issuer.AuthClaim)
	issuerAuthClaimMtp, _ := issuer.ClaimMTPRaw(t, issuer.AuthClaim)

	authClaimIncMTP, _ := user.ClaimMTPRaw(t, user.AuthClaim)
	authClaimNonRevMTP, _ := user.ClaimRevMTPRaw(t, user.AuthClaim)

	challenge := big.NewInt(10)
	signature, err := user.SignBBJJ(challenge.Bytes())
	require.NoError(t, err)

	gTree := it.GISTTree(ctx)
	err = gTree.Add(ctx, user.ID.BigInt(), user.State(t).BigInt())
	require.NoError(t, err)
	gistProof, _, err := gTree.GenerateProof(ctx, user.ID.BigInt(), nil)
	require.NoError(t, err)

	return AtomicQueryV3OnChainInputs{
		RequestID:                big.NewInt(23),
		ID:                       &user.ID,
		ProfileNonce:             big.NewInt(0),
		ClaimSubjectProfileNonce: big.NewInt(0),
		Claim: ClaimWithSigAndMTPProof{
			IssuerID: &issuer.ID,
			Claim:    claim,
			NonRevProof: MTProof{
				TreeState: TreeState{
					State:          issuer.State(t),
					ClaimsRoot:     issuer.Clt.Root(),
					RevocationRoot: issuer.Ret.Root(),
					RootOfRoots:    issuer.Rot.Root(),
				},
				Proof: issuerClaimNonRevMtp,
			},
			SignatureProof: &BJJSignatureProof{
				Signature:       claimSig,
				IssuerAuthClaim: issuer.AuthClaim,
				IssuerAuthIncProof: MTProof{
					TreeState: TreeState{
						State:          issuer.State(t),
						ClaimsRoot:     issuer.Clt.Root(),
						RevocationRoot: issuer.Ret.Root(),
						RootOfRoots:    issuer.Rot.Root(),
					},
					Proof: issuerAuthClaimMtp,
				},
				IssuerAuthNonRevProof: MTProof{
					TreeState: TreeState{
						State:          issuer.State(t),
						ClaimsRoot:     issuer.Clt.Root(),
						RevocationRoot: issuer.Ret.Root(),
						RootOfRoots:    issuer.Rot.Root(),
					},
					Proof: issuerAuthClaimNonRevMtp,
				},
			},
		},
		AuthClaim:          user.AuthClaim,
		AuthClaimIncMtp:    authClaimIncMTP,
		AuthClaimNonRevMtp: authClaimNonRevMTP,
		TreeState:          GetTreeState(t, user),
		GISTProof: GISTProof{
			Root:  gTree.Root(),
			Proof: gistProof,
		},
		Signature:        signature,
		Challenge:        challenge,
		Query:            Query{Operator: EQ, Values: []*big.Int{big.NewInt(10)}, SlotIndex: 2},
		CurrentTimeStamp: timestamp,
		ProofType:        BJJSignatureProofType,
		IsBJJAuthEnabled: 1,
	}
}

// createV3OnChainInputs_NoBJJAuth creates AtomicQueryV3OnChainInputs without BJJ auth.
func createV3OnChainInputs_NoBJJAuth(t testing.TB) AtomicQueryV3OnChainInputs {
	inputs := createV3OnChainInputs_BJJAuth(t)
	inputs.IsBJJAuthEnabled = 0
	return inputs
}
