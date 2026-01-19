package circuits

import (
	"math/big"
	"testing"

	it "github.com/iden3/go-circuits/v2/testing"
	"github.com/stretchr/testify/require"
)

func TestSelectV3TargetCircuit_SelectsFirstMatchingSubversion(t *testing.T) {
	user := it.NewIdentity(t, userPK)
	issuer := it.NewIdentity(t, issuerPK)

	subjectID := user.ID
	profileNonce := big.NewInt(0)
	_ = profileNonce

	claim := it.DefaultUserClaim(t, subjectID)

	issuerClaimNonRevMtp, _ := issuer.ClaimRevMTPRaw(t, claim)
	issuerAuthClaimMtp, _ := issuer.ClaimMTPRaw(t, issuer.AuthClaim)
	issuerAuthClaimNonRevMtp, _ := issuer.ClaimRevMTPRaw(t, issuer.AuthClaim)

	require.NotNil(t, issuerClaimNonRevMtp)
	require.NotNil(t, issuerAuthClaimMtp)
	require.NotNil(t, issuerAuthClaimNonRevMtp)

	mtSiblings := len(issuerClaimNonRevMtp.AllSiblings())
	claimSiblings := len(issuerAuthClaimMtp.AllSiblings())

	failMT := mtSiblings
	passMT := mtSiblings + 1
	passClaim := claimSiblings + 1

	const testCircuit CircuitID = AtomicQueryV3OnChainStableCircuitID

	orig, had := CircuitValidator[testCircuit]
	t.Cleanup(func() {
		if had {
			CircuitValidator[testCircuit] = orig
		} else {
			delete(CircuitValidator, testCircuit)
		}
	})

	CircuitValidator[testCircuit] = CircuitValidatorItem{
		SubVersions: []CircuitSubversion{
			{
				MTLevel:         intPtr(failMT),
				MTLevelClaim:    intPtr(passClaim),
				TargetCircuitId: "bad-subversion",
			},
			{
				MTLevel:         intPtr(passMT),
				MTLevelClaim:    intPtr(passClaim),
				TargetCircuitId: "good-subversion",
			},
		},
	}

	proofsToCheck := []TreesToCheck{
		{Proof: issuerClaimNonRevMtp, LevelKey: LevelMT},
		{Proof: issuerAuthClaimMtp, LevelKey: LevelMT},
		{Proof: issuerAuthClaimNonRevMtp, LevelKey: LevelMT},
		{Proof: issuerClaimNonRevMtp, LevelKey: LevelMT},
		{Proof: issuerAuthClaimMtp, LevelKey: LevelMTClaim},
	}

	got := SelectV3TargetCircuit(testCircuit, proofsToCheck, false)
	require.NotNil(t, got)
	require.Equal(t, CircuitID("good-subversion"), got.TargetCircuitId)
	require.Equal(t, passMT, *got.MTLevel)
	require.Equal(t, passClaim, *got.MTLevelClaim)
}

func TestSelectV3TargetCircuit_OnChain_RequiresMTLevelOnChain(t *testing.T) {
	user := it.NewIdentity(t, userPK)
	issuer := it.NewIdentity(t, issuerPK)
	claim := it.DefaultUserClaim(t, user.ID)
	p, _ := issuer.ClaimRevMTPRaw(t, claim)
	require.NotNil(t, p)

	siblings := len(p.AllSiblings())
	pass := siblings + 1

	const testCircuit CircuitID = AtomicQueryV3OnChainCircuitID

	orig, had := CircuitValidator[testCircuit]
	t.Cleanup(func() {
		if had {
			CircuitValidator[testCircuit] = orig
		} else {
			delete(CircuitValidator, testCircuit)
		}
	})

	CircuitValidator[testCircuit] = CircuitValidatorItem{
		SubVersions: []CircuitSubversion{
			{
				MTLevel:         intPtr(pass),
				MTLevelClaim:    intPtr(pass),
				MTLevelOnChain:  nil,
				TargetCircuitId: "bad-missing-onchain",
			},
			{
				MTLevel:         intPtr(pass),
				MTLevelClaim:    intPtr(pass),
				MTLevelOnChain:  intPtr(pass),
				TargetCircuitId: "good-onchain",
			},
		},
	}

	proofsToCheck := []TreesToCheck{
		{Proof: p, LevelKey: LevelMT},
		{Proof: p, LevelKey: LevelMTClaim},
		{Proof: p, LevelKey: LevelMTOnChain},
	}

	got := SelectV3TargetCircuit(testCircuit, proofsToCheck, true)
	require.NotNil(t, got)
	require.Equal(t, CircuitID("good-onchain"), got.TargetCircuitId)
	require.Equal(t, pass, *got.MTLevelOnChain)
}

func TestSelectLinkedMultiQueryCircuit_Special10(t *testing.T) {
	sv, err := SelectLinkedMultiQueryCircuit(LinkedMultiQuery10CircuitID, 1)
	require.NoError(t, err)
	require.NotNil(t, sv)
	require.Equal(t, LinkedMultiQuery10CircuitID, sv.TargetCircuitId)
	require.NotNil(t, sv.QueryCount)
	require.Equal(t, 10, *sv.QueryCount)

	sv2, err := SelectLinkedMultiQueryCircuit(LinkedMultiQuery10CircuitID, 11)
	require.Error(t, err)
	require.Nil(t, sv2)

	sv3, err := SelectLinkedMultiQueryCircuit(LinkedMultiQueryStableCircuitID, 11)
	require.Error(t, err)
	require.Nil(t, sv3)
}

func TestSelectLinkedMultiQueryCircuit_StableSelection(t *testing.T) {
	tests := []struct {
		name         string
		queriesCount int
		wantQC       int
		wantTarget   CircuitID
	}{
		{"1->3", 1, 3, CircuitID(string(LinkedMultiQueryStableCircuitID) + "3")},
		{"3->3", 3, 3, CircuitID(string(LinkedMultiQueryStableCircuitID) + "3")},
		{"4->5", 4, 5, CircuitID(string(LinkedMultiQueryStableCircuitID) + "5")},
		{"5->5", 5, 5, CircuitID(string(LinkedMultiQueryStableCircuitID) + "5")},
		{"6->10", 6, 10, CircuitID(string(LinkedMultiQueryStableCircuitID))},
		{"10->10", 10, 10, CircuitID(string(LinkedMultiQueryStableCircuitID))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sv, err := SelectLinkedMultiQueryCircuit(LinkedMultiQueryStableCircuitID, tt.queriesCount)
			require.NoError(t, err)
			require.NotNil(t, sv)
			require.NotNil(t, sv.QueryCount)
			require.Equal(t, tt.wantQC, *sv.QueryCount)
			require.Equal(t, tt.wantTarget, sv.TargetCircuitId)
		})
	}
}

func TestSelectLinkedMultiQueryCircuit_NoValidatorEntry(t *testing.T) {
	orig, hadOrig := CircuitValidator[LinkedMultiQueryStableCircuitID]
	delete(CircuitValidator, LinkedMultiQueryStableCircuitID)
	t.Cleanup(func() {
		if hadOrig {
			CircuitValidator[LinkedMultiQueryStableCircuitID] = orig
		}
	})

	sv, err := SelectLinkedMultiQueryCircuit(LinkedMultiQueryStableCircuitID, 1)
	require.Nil(t, sv)
	require.Error(t, err)
}
