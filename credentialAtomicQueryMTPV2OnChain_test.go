package circuits

import (
	"context"
	"encoding/json"
	"math/big"
	"testing"

	it "github.com/iden3/go-circuits/testing"
	"github.com/stretchr/testify/require"
)

func TestAttrQueryMTPV2OnChain_PrepareInputs(t *testing.T) {
	challenge := big.NewInt(10)

	// generate identity
	user := it.NewIdentity(t, userPK)
	nonce := big.NewInt(0)

	user2 := it.NewIdentity(t, issuerPK)

	// generate global tree
	gTree := it.GlobalTree(context.Background())

	err := gTree.Add(context.Background(), user2.ID.BigInt(), user2.State(t).BigInt())
	require.NoError(t, err)

	// prepare inputs
	globalProof, _, err := gTree.GenerateProof(context.Background(), user.ID.BigInt(), nil)
	require.NoError(t, err)

	authClaimIncMTP, _ := user.ClaimMTPRaw(t, user.AuthClaim)

	authClaimNonRevMTP, _ := user.ClaimRevMTPRaw(t, user.AuthClaim)
	require.NoError(t, err)

	signature, err := user.SignBBJJ(challenge.Bytes())
	issuer := it.NewIdentity(t, issuerPK)

	subjectID := user.ID
	nonceSubject := big.NewInt(0)

	claim := it.DefaultUserClaim(t, subjectID)

	issuer.AddClaim(t, claim)

	issuerClaimMtp, _ := issuer.ClaimMTPRaw(t, claim)

	issuerClaimNonRevMtp, _ := issuer.ClaimRevMTPRaw(t, claim)

	in := AtomicQueryMTPV2OnChainInputs{
		RequestID:                big.NewInt(23),
		ID:                       &user.ID,
		ProfileNonce:             nonce,
		ClaimSubjectProfileNonce: nonceSubject,
		Claim: ClaimWithMTPProof{
			IssuerID: &issuer.ID,
			Claim:    claim,
			IncProof: MTProof{
				Proof: issuerClaimMtp,
				TreeState: TreeState{
					State:          issuer.State(t),
					ClaimsRoot:     issuer.Clt.Root(),
					RevocationRoot: issuer.Ret.Root(),
					RootOfRoots:    issuer.Rot.Root(),
				},
			},
			NonRevProof: MTProof{
				TreeState: TreeState{
					State:          issuer.State(t),
					ClaimsRoot:     issuer.Clt.Root(),
					RevocationRoot: issuer.Ret.Root(),
					RootOfRoots:    issuer.Rot.Root(),
				},
				Proof: issuerClaimNonRevMtp,
			},
		},
		Query: Query{
			ValueProof: nil,
			Operator:   EQ,
			Values:     it.PrepareIntArray([]*big.Int{big.NewInt(10)}, 64),
			SlotIndex:  2,
		},
		CurrentTimeStamp:   timestamp,
		AuthClaim:          user.AuthClaim,
		AuthClaimIncMtp:    authClaimIncMTP,
		AuthClaimNonRevMtp: authClaimNonRevMTP,
		TreeState:          GetTreeState(t, user),
		GISTProof: GISTProof{
			Root:  gTree.Root(),
			Proof: globalProof,
		},
		Signature: signature,
		Challenge: challenge,
	}

	bytesInputs, err := in.InputsMarshal()
	require.Nil(t, err)
	exp := it.TestData(t, "mtpV2OnChain_inputs", string(bytesInputs), *generate)
	t.Log(string(bytesInputs))
	require.JSONEq(t, exp, string(bytesInputs))

}

func TestAtomicQueryMTPVOnChain2Outputs_CircuitUnmarshal(t *testing.T) {
	out := new(AtomicQueryMTPV2OnChainPubSignals)
	err := out.PubSignalsUnmarshal([]byte(`[
 "0",
 "26109404700696283154998654512117952420503675471097392618762221546565140481",
 "9733373854039911298636091230039813139726844451320966546058337263014541694144",
 "23",
 "10",
 "11098939821764568131087645431296528907277253709936443029379587475821759259406",
 "27918766665310231445021466320959318414450284884582375163563581940319453185",
 "19157496396839393206871475267813888069926627705277243727237933406423274512449",
 "1",
 "19157496396839393206871475267813888069926627705277243727237933406423274512449",
 "1642074362",
 "180410020913331409885634153623124536270",
 "1",
 "0",
 "2",
 "1"]`))
	require.NoError(t, err)
	challenge := big.NewInt(10)

	value, err := PrepareCircuitArrayValues([]*big.Int{big.NewInt(10)}, 64)
	require.NoError(t, err)
	valueHash, err := PoseidonHashValue(value)
	require.NoError(t, err)

	exp := AtomicQueryMTPV2OnChainPubSignals{
		RequestID: big.NewInt(23),
		UserID: it.IDFromStr(
			t, "26109404700696283154998654512117952420503675471097392618762221546565140481"),
		IssuerID: it.IDFromStr(t,
			"27918766665310231445021466320959318414450284884582375163563581940319453185"),
		IssuerClaimIdenState: it.MTHashFromStr(t,
			"19157496396839393206871475267813888069926627705277243727237933406423274512449"),
		IssuerClaimNonRevState: it.MTHashFromStr(t, "19157496396839393206871475267813888069926627705277243727237933406423274512449"),
		ClaimSchema:            it.CoreSchemaFromStr(t, "180410020913331409885634153623124536270"),
		SlotIndex:              2,
		Operator:               1,
		ValueHash:              valueHash,
		Timestamp:              int64(1642074362),
		Merklized:              0,
		ClaimPathKey:           big.NewInt(0),
		ClaimPathNotExists:     1,
		IsRevocationChecked:    1,
		Challenge:              challenge,
		GlobalRoot:             it.MTHashFromStr(t, "11098939821764568131087645431296528907277253709936443029379587475821759259406"),
	}

	jsonOut, err := json.Marshal(out)
	require.NoError(t, err)
	jsonExp, err := json.Marshal(exp)
	require.NoError(t, err)

	require.JSONEq(t, string(jsonExp), string(jsonOut))
}
