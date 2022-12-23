package circuits

import (
	"context"
	"encoding/json"
	it "github.com/iden3/go-circuits/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func TestSybilSig_PrepareInputs(t *testing.T) {

	user := it.NewIdentity(t, userPK)

	issuer := it.NewIdentity(t, issuerPK)

	subjectID := user.ID
	profileNonce := big.NewInt(0)

	nonceSubject := big.NewInt(0)

	claim := it.DefaultUserClaim(t, subjectID)

	// Sig claim
	claimSig := issuer.SignClaim(t, claim)

	issuerClaimNonRevMtp, _ := issuer.ClaimRevMTPRaw(t, claim)

	issuerAuthClaimNonRevMtp, _ := issuer.ClaimRevMTPRaw(t, issuer.AuthClaim)
	issuerAuthClaimMtp, _ := issuer.ClaimMTPRaw(t, issuer.AuthClaim)

	crs := new(big.Int).SetInt64(1234).String()
	ssClaim := it.UserStateSecretClaim(t, new(big.Int).SetInt64(5555))
	user.AddClaim(t, ssClaim)
	userClaimMtp, _ := user.ClaimMTPRaw(t, ssClaim)

	gTree := it.GlobalTree(context.Background())
	err := gTree.Add(context.Background(), user.ID.BigInt(), user.State(t).BigInt())
	require.NoError(t, err)

	globalProof, _, err := gTree.GenerateProof(context.Background(), user.ID.BigInt(), nil)
	require.NoError(t, err)

	in := SybilSigInputs{
		ID:                       &user.ID,
		ProfileNonce:             profileNonce,
		ClaimSubjectProfileNonce: nonceSubject,
		UniClaim: ClaimWithSigProof{
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
			SignatureProof: BJJSignatureProof{
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
		CRS: crs,
		StateSecretClaim: ClaimWithMTPProof{
			Claim: ssClaim,
			IncProof: MTProof{
				Proof: userClaimMtp,
				TreeState: TreeState{
					State:          user.State(t),
					ClaimsRoot:     user.Clt.Root(),
					RevocationRoot: user.Ret.Root(),
					RootOfRoots:    user.Rot.Root(),
				},
			},
			IssuerID: &user.ID,
		},
		GISTProof: GISTProof{
			Root:  gTree.Root(),
			Proof: globalProof,
		},
	}

	circuitInputJSON, err := in.InputsMarshal()
	assert.Nil(t, err)

	exp := it.TestData(t, "sybilSig_inputs", string(circuitInputJSON), *generate)
	t.Log(string(circuitInputJSON))

	require.JSONEq(t, exp, string(circuitInputJSON))
}

func TestSybilSigOutputs_CircuitUnmarshal(t *testing.T) {
	out := new(SybilSigPubSignals)
	err := out.PubSignalsUnmarshal([]byte(`[
	 "20177832565449474772630743317224985532862797657496372535616634430055981993180",
	 "1234",
	 "12237249731937050748239754514110031073443409881058925518681107238397055045148"
	]`))
	require.NoError(t, err)

	exp := SybilSigPubSignals{
		IssuerClaimNonRevState: it.MTHashFromStr(t, "20177832565449474772630743317224985532862797657496372535616634430055981993180"),
		CRS:                    "1234",
		GISTRoot:               it.MTHashFromStr(t, "12237249731937050748239754514110031073443409881058925518681107238397055045148"),
	}

	jsonOut, err := json.Marshal(out)
	require.NoError(t, err)
	jsonExp, err := json.Marshal(exp)
	require.NoError(t, err)

	require.JSONEq(t, string(jsonExp), string(jsonOut))
}
