package circuits

import (
	"context"
	"encoding/json"
	it "github.com/iden3/go-circuits/testing"
	core "github.com/iden3/go-iden3-core"
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

	requestID := new(big.Int).SetInt64(123)
	currentTimestamp := int64(1642074362)

	claim := it.DefaultUserClaim(t, subjectID)

	claimSig := issuer.SignClaim(t, claim)

	issuerClaimNonRevMtp, _ := issuer.ClaimRevMTPRaw(t, claim)

	issuerAuthClaimNonRevMtp, _ := issuer.ClaimRevMTPRaw(t, issuer.AuthClaim)
	issuerAuthClaimMtp, _ := issuer.ClaimMTPRaw(t, issuer.AuthClaim)

	crs, ok := new(big.Int).SetString("249532670194878832589534456260980839355904887861263878269048090946773573111", 10)
	if ok == false {
		t.Fatal("failed to set crs")
	}

	commClaim := it.UserStateCommitmentClaim(t, new(big.Int).SetInt64(5555))
	user.AddClaim(t, commClaim)
	userClaimMtp, _ := user.ClaimMTPRaw(t, commClaim)

	gTree := it.GISTTree(context.Background())
	err := gTree.Add(context.Background(), user.ID.BigInt(), user.State(t).BigInt())
	require.NoError(t, err)

	gistProof, _, err := gTree.GenerateProof(context.Background(), user.ID.BigInt(), nil)
	require.NoError(t, err)

	in := SybilAtomicSigInputs{
		ID:                       &user.ID,
		ProfileNonce:             profileNonce,
		ClaimSubjectProfileNonce: nonceSubject,
		IssuerClaim: ClaimWithSigProof{
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
		StateCommitmentClaim: ClaimWithMTPProof{
			Claim: commClaim,
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
			Proof: gistProof,
		},
		RequestID: requestID,
		Timestamp: currentTimestamp,
	}

	circuitInputJSON, err := in.InputsMarshal()
	assert.Nil(t, err)

	exp := it.TestData(t, "sybilSig_inputs", string(circuitInputJSON), *generate)
	t.Log(string(circuitInputJSON))

	require.JSONEq(t, exp, string(circuitInputJSON))
}

func TestSybilSigOutputs_CircuitUnmarshal(t *testing.T) {
	out := new(SybilAtomicSigPubSignals)

	err := out.PubSignalsUnmarshal([]byte(`[
	 "223724973193705074823975451411003107344340988105892551868110723839705504514",
	 "223724973193705074823975451411003107344340988105892551868110723839705504514",
	 "26109404700696283154998654512117952420503675471097392618762221546565140481",
	 "20177832565449474772630743317224985532862797657496372535616634430055981993180",
     "180410020913331409885634153623124536270",
	 "12237249731937050748239754514110031073443409881058925518681107238397055045148",
	 "249532670194878832589534456260980839355904887861263878269048090946773573111",
	 "123",
	 "27918766665310231445021466320959318414450284884582375163563581940319453185",
	 "1642074362"
	]`))
	require.NoError(t, err)

	user := it.NewIdentity(t, userPK)

	issuer := it.NewIdentity(t, issuerPK)

	issuerClaimSchema, ok := new(big.Int).SetString("180410020913331409885634153623124536270", 10)
	if ok == false {
		t.Fatalf("new(big.Int).SetString has faild")
	}

	sybilID, ok := new(big.Int).SetString("223724973193705074823975451411003107344340988105892551868110723839705504514", 10)
	if ok == false {
		t.Fatalf("new(big.Int).SetString has faild")
	}

	crs, ok := new(big.Int).SetString("249532670194878832589534456260980839355904887861263878269048090946773573111", 10)
	if ok == false {
		t.Fatal("failed to set crs")
	}

	exp := SybilAtomicSigPubSignals{
		IssuerClaimNonRevState: it.MTHashFromStr(t, "20177832565449474772630743317224985532862797657496372535616634430055981993180"),
		CRS:                    crs,
		GISTRoot:               it.MTHashFromStr(t, "12237249731937050748239754514110031073443409881058925518681107238397055045148"),
		IssuerID:               &issuer.ID,
		RequestID:              new(big.Int).SetInt64(123),
		Timestamp:              1642074362,
		UserID:                 &user.ID,
		ClaimSchema:            core.NewSchemaHashFromInt(issuerClaimSchema),
		SybilID:                sybilID,
		IssuerAuthState:        it.MTHashFromStr(t, "223724973193705074823975451411003107344340988105892551868110723839705504514"),
	}

	jsonOut, err := json.Marshal(out)
	require.NoError(t, err)
	jsonExp, err := json.Marshal(exp)
	require.NoError(t, err)

	require.JSONEq(t, string(jsonExp), string(jsonOut))
}
