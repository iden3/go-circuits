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

func TestSybilMTP_PrepareInputs(t *testing.T) {

	user := it.NewIdentity(t, userPK)

	issuer := it.NewIdentity(t, issuerPK)

	subjectID := user.ID
	profileNonce := big.NewInt(0)

	nonceSubject := big.NewInt(0)

	requestID := new(big.Int).SetInt64(123)
	currentTimestamp := int64(1642074362)

	claim := it.DefaultUserClaim(t, subjectID)

	issuer.AddClaim(t, claim)

	issuerClaimMtp, _ := issuer.ClaimMTPRaw(t, claim)

	issuerClaimNonRevMtp, _ := issuer.ClaimRevMTPRaw(t, claim)

	crs := new(big.Int).SetInt64(1234)
	ssClaim := it.UserStateSecretClaim(t, new(big.Int).SetInt64(5555))
	user.AddClaim(t, ssClaim)
	userClaimMtp, _ := user.ClaimMTPRaw(t, ssClaim)

	gTree := it.GlobalTree(context.Background())
	err := gTree.Add(context.Background(), user.ID.BigInt(), user.State(t).BigInt())
	require.NoError(t, err)

	globalProof, _, err := gTree.GenerateProof(context.Background(), user.ID.BigInt(), nil)
	require.NoError(t, err)

	in := SybilAtomicMTPInputs{
		ID:                       &user.ID,
		ProfileNonce:             profileNonce,
		ClaimSubjectProfileNonce: nonceSubject,
		IssuerClaim: ClaimWithMTPProof{
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
			IncProof: MTProof{
				Proof: issuerClaimMtp,
				TreeState: TreeState{
					State:          issuer.State(t),
					ClaimsRoot:     issuer.Clt.Root(),
					RevocationRoot: issuer.Ret.Root(),
					RootOfRoots:    issuer.Rot.Root(),
				},
			},
		},
		CRS: crs,
		StateCommitmentClaim: ClaimWithMTPProof{
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
		RequestID: requestID,
		Timestamp: currentTimestamp,
	}

	circuitInputJSON, err := in.InputsMarshal()
	assert.Nil(t, err)

	exp := it.TestData(t, "sybilMTP_inputs", string(circuitInputJSON), *generate)
	t.Log(string(circuitInputJSON))

	require.JSONEq(t, exp, string(circuitInputJSON))
}

func TestSybilMTPOutputs_CircuitUnmarshal(t *testing.T) {
	out := new(SybilAtomicMTPPubSignals)
	err := out.PubSignalsUnmarshal([]byte(`[
		 "26109404700696283154998654512117952420503675471097392618762221546565140481",
		 "223724973193705074823975451411003107344340988105892551868110723839705504514",
		 "123",
		 "27918766665310231445021466320959318414450284884582375163563581940319453185",
	     "1642074362",
		 "19157496396839393206871475267813888069926627705277243727237933406423274512449",
		 "19157496396839393206871475267813888069926627705277243727237933406423274512449",
		 "180410020913331409885634153623124536270",
		 "1234",
		 "12237249731937050748239754514110031073443409881058925518681107238397055045148"
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

	exp := SybilAtomicMTPPubSignals{
		IssuerClaimNonRevState: it.MTHashFromStr(t, "19157496396839393206871475267813888069926627705277243727237933406423274512449"),
		CRS:                    new(big.Int).SetInt64(1234),
		GISTRoot:               it.MTHashFromStr(t, "12237249731937050748239754514110031073443409881058925518681107238397055045148"),
		IssuerClaimIdenState:   it.MTHashFromStr(t, "19157496396839393206871475267813888069926627705277243727237933406423274512449"),
		IssuerID:               &issuer.ID,
		RequestID:              new(big.Int).SetInt64(123),
		Timestamp:              1642074362,
		UserID:                 &user.ID,
		ClaimSchema:            core.NewSchemaHashFromInt(issuerClaimSchema),
		SybilID:                sybilID,
	}

	jsonOut, err := json.Marshal(out)
	require.NoError(t, err)
	jsonExp, err := json.Marshal(exp)
	require.NoError(t, err)

	require.JSONEq(t, string(jsonExp), string(jsonOut))
}
